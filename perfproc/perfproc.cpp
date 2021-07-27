#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define INITGUID
#include <Windows.h>
#include <VersionHelpers.h>
#include <Unknwn.h>
#include <guiddef.h>
#include <wil/cppwinrt.h>
#include <winrt/base.h>
#include <wil/win32_helpers.h>
#include <wil/resource.h>
#include <comdef.h>

#include <evntrace.h>
#include <evntcons.h>
#include <relogger.h>

#include <optional>
#include <unordered_set>
#include <locale>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cassert>

#include <KernelTraceControl.h>

#include "CLI11.hpp"

DEFINE_GUID( /* 2cb15d1d-5fc1-11d2-abe1-00a0c911f518 */
	ImageLoadGuid,
	0x2cb15d1d,
	0x5fc1,
	0x11d2,
	0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18
);

DEFINE_GUID( /* ce1dbfb4-137e-4da6-87b0-3f59aa102cbc */
	PerfInfoGuid,
	0xce1dbfb4,
	0x137e,
	0x4da6,
	0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc
);

DEFINE_GUID( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
	ProcessGuid,
	0x3d6fa8d0,
	0xfe05,
	0x11d0,
	0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);

DEFINE_GUID( /* 3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c */
	ThreadGuid,
	0x3d6fa8d1,
	0xfe05,
	0x11d0,
	0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);

DEFINE_GUID( /* def2fe46-7bd6-4b80-bd94-f57fe20d0ce3 */
	StackWalkGuid,
	0xdef2fe46,
	0x7bd6,
	0x4b80,
	0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3);

struct COMInitializer
{
	COMInitializer()
	{
		winrt::init_apartment();
	}
	~COMInitializer()
	{
		winrt::clear_factory_cache();
		winrt::uninit_apartment();
	}
};

template <typename Ptr>
struct Process_V2_V3_V4_TypeGroup1_Header
{
	Ptr UniqueProcessKey_Or_PageDirectoryBase;
	uint32_t ProcessId;
	// ...
};

template <typename Ptr>
struct SampledProfile_V1_V2_Header
{
	Ptr InstructionPointer;
	uint32_t ThreadId;
	// ...
};

struct Thread_V1_V2_V3_V4_TypeGroup1_Header
{
	uint32_t ProcessId;
	uint32_t ThreadId;
	// ...
};

template <typename Ptr>
struct ImageLoad_V1_V2_V3_V4_Header
{
	Ptr ImageBase;
	Ptr ImageSize;
	uint32_t ProcessId;
	// ...
};

struct StackWalk_Header
{
	uint64_t EventTimeStamp;
	uint32_t StackProcess;
	uint32_t StackThread;
	// ...
};

template <typename Ptr>
static std::optional<ULONG> getSampledProfileEventTID(const EVENT_RECORD& eventRecord)
{
	if (eventRecord.UserDataLength >= sizeof(SampledProfile_V1_V2_Header<Ptr>)) {
		const auto hdr = static_cast<const SampledProfile_V1_V2_Header<Ptr>*>(eventRecord.UserData);
		return hdr->ThreadId;
	}

	return std::nullopt;
}

static std::optional<ULONG> getSampledProfileEventTID(const EVENT_RECORD& eventRecord)
{
	const bool is64Bit = (eventRecord.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
	if (is64Bit) {
		return getSampledProfileEventTID<uint64_t>(eventRecord);
	} else {
		return getSampledProfileEventTID<uint32_t>(eventRecord);
	}
}

template <typename Ptr>
static std::optional<ULONG> getProcessEventPIDImpl(const EVENT_RECORD& eventRecord)
{
	if (eventRecord.UserDataLength >= sizeof(Process_V2_V3_V4_TypeGroup1_Header<Ptr>)) {
		const auto hdr = static_cast<const Process_V2_V3_V4_TypeGroup1_Header<Ptr>*>(eventRecord.UserData);
		return hdr->ProcessId;
	}

	return std::nullopt;
}

static std::optional<ULONG> getProcessEventPID(const EVENT_RECORD& eventRecord)
{
	const bool is64Bit = (eventRecord.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
	if (is64Bit) {
		return getProcessEventPIDImpl<uint64_t>(eventRecord);
	} else {
		return getProcessEventPIDImpl<uint32_t>(eventRecord);
	}
}

template <typename Ptr>
static std::optional<ULONG> getImageLoadEventPIDImpl(const EVENT_RECORD& eventRecord)
{
	if (eventRecord.UserDataLength >= sizeof(ImageLoad_V1_V2_V3_V4_Header<Ptr>)) {
		const auto hdr = static_cast<const ImageLoad_V1_V2_V3_V4_Header<Ptr>*>(eventRecord.UserData);
		return hdr->ProcessId;
	}

	return std::nullopt;
}

static std::optional<ULONG> getImageLoadEventPID(const EVENT_RECORD& eventRecord)
{
	const bool is64Bit = (eventRecord.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
	if (is64Bit) {
		return getImageLoadEventPIDImpl<uint64_t>(eventRecord);
	} else {
		return getImageLoadEventPIDImpl<uint32_t>(eventRecord);
	}
}

static std::optional<ULONG> getStackWalkEventPID(const EVENT_RECORD& eventRecord)
{
	const auto hdr = static_cast<const StackWalk_Header*>(eventRecord.UserData);
	if (eventRecord.UserDataLength >= sizeof(StackWalk_Header)) {
		return hdr->StackProcess;
	}

	return std::nullopt;
}

class TraceCallback : public winrt::implements<TraceCallback, ITraceEventCallback>
{
private:
	using EventRecordHandler = bool (TraceCallback::*)(const EVENT_RECORD&);

	static const std::unordered_map<winrt::guid, EventRecordHandler> handlers;

	ULONG _targetPid{};
	std::unordered_set<ULONG> _tids;

	bool onEventTraceEvent([[maybe_unused]] const EVENT_RECORD& eventRecord)
	{
		return true;
	}

	bool onImageLoadEvent(const EVENT_RECORD& eventRecord)
	{
		bool shouldInject = false;

		switch (eventRecord.EventHeader.EventDescriptor.Opcode) {
		case EVENT_TRACE_TYPE_LOAD:
		case EVENT_TRACE_TYPE_STOP:
		case EVENT_TRACE_TYPE_DC_START:
		case EVENT_TRACE_TYPE_DC_END:
		{
			const auto pid = getImageLoadEventPID(eventRecord);
			shouldInject = (pid == 0) || (pid == 4) || (pid == _targetPid);
		}
			break;
		default:
			break;
		}

		return shouldInject;
	}

	bool onPerfInfoEvent(const EVENT_RECORD& eventRecord)
	{
		bool shouldInject = false;

		constexpr UCHAR SAMPLED_PROFILE = 46;
		switch (eventRecord.EventHeader.EventDescriptor.Opcode) {
		case SAMPLED_PROFILE:
		{
			auto tid = getSampledProfileEventTID(eventRecord);
			if (tid.has_value()) {
				shouldInject = _tids.contains(tid.value());
			}
		}
			break;
		default:
			break;
		}
		return shouldInject;
	}

	bool onStackWalkEvent(const EVENT_RECORD& eventRecord)
	{
		bool shouldInject = false;
		constexpr UCHAR STACKWALK = 32;

		switch (eventRecord.EventHeader.EventDescriptor.Opcode) {
		case STACKWALK:
			shouldInject = getStackWalkEventPID(eventRecord) == _targetPid;
			break;
		default:
			__debugbreak();
			break;
		}

		return shouldInject;
	}

	bool onThreadEvent(const EVENT_RECORD& eventRecord)
	{
		bool shouldInject = false;

		const auto& opcode = eventRecord.EventHeader.EventDescriptor.Opcode;
		switch (opcode) {
		case EVENT_TRACE_TYPE_START:
		case EVENT_TRACE_TYPE_STOP:
		case EVENT_TRACE_TYPE_DC_START:
		case EVENT_TRACE_TYPE_DC_END:
		{
			const auto hdr = static_cast<const Thread_V1_V2_V3_V4_TypeGroup1_Header*>(eventRecord.UserData);
			if (eventRecord.UserDataLength >= sizeof(Thread_V1_V2_V3_V4_TypeGroup1_Header)) {
				if (hdr->ProcessId == _targetPid) {
					shouldInject = true;

					if ((opcode == EVENT_TRACE_TYPE_START) || (opcode == EVENT_TRACE_TYPE_DC_START)) {
						_tids.insert(hdr->ThreadId);
					} else if (opcode == EVENT_TRACE_TYPE_STOP) {
						_tids.erase(hdr->ThreadId);
					}
				}
			}
		}
			break;
		default:
			break;
		}

		return shouldInject;
	}

	bool onProcessEvent(const EVENT_RECORD& eventRecord)
	{
		bool shouldInject = false;

		switch (eventRecord.EventHeader.EventDescriptor.Opcode) {
		case EVENT_TRACE_TYPE_START:
		case EVENT_TRACE_TYPE_STOP:
		case EVENT_TRACE_TYPE_DC_START:
		case EVENT_TRACE_TYPE_DC_END:
			switch (eventRecord.EventHeader.EventDescriptor.Version) {
			case 1:
			case 2:
			case 3:
			case 4:
				if (getProcessEventPID(eventRecord) == _targetPid) {
					shouldInject = true;
				}
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}

		return shouldInject;
	}

public:
	TraceCallback(ULONG targetPid) : _targetPid{ targetPid }
	{

	}

	HRESULT STDMETHODCALLTYPE OnBeginProcessTrace(
		__RPC__in_opt [[maybe_unused]] ITraceEvent* HeaderEvent,
		__RPC__in_opt [[maybe_unused]] ITraceRelogger* Relogger) override
	{
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE OnFinalizeProcessTrace(
		__RPC__in_opt [[maybe_unused]] ITraceRelogger* Relogger) override
	{
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE OnEvent(
		__RPC__in_opt ITraceEvent* Event,
		__RPC__in_opt ITraceRelogger* Relogger) override
	{
		HRESULT hr{};

		EVENT_RECORD* eventRecord{};
		hr = Event->GetEventRecord(&eventRecord);
		if (FAILED(hr)) {
			return hr;
		}

		bool shouldInject = false;

		const auto& provId = eventRecord->EventHeader.ProviderId;
		const auto it = handlers.find(provId);
		if (it != end(handlers)) {
			shouldInject = (this->*(it->second))(*eventRecord);
		} else {
			__debugbreak();
		}

		const ULONG& pid = eventRecord->EventHeader.ProcessId;

		if (!shouldInject) {
			if (pid == _targetPid) {
				shouldInject = true;
			}
		}

		if (shouldInject) {
			hr = Relogger->Inject(Event);
		}

		return hr;
	}
};

const std::unordered_map<winrt::guid, TraceCallback::EventRecordHandler> TraceCallback::handlers{
	{ EventTraceGuid, &TraceCallback::onEventTraceEvent },
	{ EventTraceConfigGuid, &TraceCallback::onEventTraceEvent },
	{ ImageLoadGuid, &TraceCallback::onImageLoadEvent },
	{ PerfInfoGuid, &TraceCallback::onPerfInfoEvent },
	{ StackWalkGuid, &TraceCallback::onStackWalkEvent },
	{ ThreadGuid, &TraceCallback::onThreadEvent },
	{ ProcessGuid, &TraceCallback::onProcessEvent }
};

static std::wstring widen(std::string_view s)
{
	mbstate_t st{};
	const char* p = s.data();
	size_t needed = 0;
	errno_t e = mbsrtowcs_s(&needed, nullptr, 0, &p, s.size(), &st);
	std::wstring w(needed - 1, L'\0');
	p = s.data(); st = {};
	e = mbsrtowcs_s(&needed, w.data(), w.size() + 1, &p, s.size(), &st);

	return w;
}

int main(int argc, const char* argv[])
{
	std::locale::global(std::locale(".UTF8"));

	CLI::App app{ "Filter ETW session to a specific process" };

	std::string realTimeSession;
	auto realtimeOption = app.add_option("-r,--realtime", realTimeSession, "Name of existing real-time ETW session to consume");

	std::string logFileName;
	auto logFileNameOption = app.add_option("-l,--logfile", logFileName, "Name of existing ETW log to consume");
	logFileNameOption->excludes(realtimeOption);
	logFileNameOption->check(CLI::ExistingFile);

	ULONG pid{};
	auto pidOption = app.add_option("-p,--pid", pid, "Process id to filter");
	pidOption->required();

	bool compress = true;
	auto compressionOption = app.add_flag("-c,--compress,!--no-compress", compress, "Compress output file");

	std::string outputFileName;
	auto outputFileOption = app.add_option("-o,--output", outputFileName, "Output file name");
	outputFileOption->required();

	std::string mergedFileName;
	auto mergedFileOption = app.add_option("--merged", mergedFileName, "Merged file name");

	bool merge = true;
	auto mergeOption = app.add_flag("-m,--merge,!--no-merge", merge, "Merge output file with injected extended data");

	DWORD extendedDataFlags = EVENT_TRACE_MERGE_EXTENDED_DATA_ALL;
	auto edfOption = app.add_option("--merge-flags", extendedDataFlags, "Extended data flags for merge");

	CLI11_PARSE(app, argc, argv);

	HRESULT hr{};
	COMInitializer ci;

	auto traceRelogger = winrt::try_create_instance<ITraceRelogger>(_uuidof(CTraceRelogger));
	if (!traceRelogger) {
		fwprintf(stderr, L"Failed creating trace relogger.");
		return EXIT_FAILURE;
	}

	TRACEHANDLE traceHandle{};

	if (*realtimeOption) {
		hr = traceRelogger->AddRealtimeTraceStream(_bstr_t(widen(realTimeSession).c_str()), nullptr, &traceHandle);
	} else if (*logFileNameOption) {
		hr = traceRelogger->AddLogfileTraceStream(_bstr_t(widen(logFileName).c_str()), nullptr, &traceHandle);
	}
	winrt::check_hresult(hr);

	auto traceCallback = winrt::make<TraceCallback>(pid);
	
	hr = traceRelogger->RegisterCallback(winrt::get_abi(traceCallback));
	winrt::check_hresult(hr);

	hr = traceRelogger->SetCompressionMode(compress ? TRUE : FALSE);
	winrt::check_hresult(hr);

	std::wstring wideOutputFileName = widen(outputFileName);
	hr = traceRelogger->SetOutputFilename(_bstr_t(wideOutputFileName.c_str()));
	winrt::check_hresult(hr);

	hr = traceRelogger->ProcessTrace();
	winrt::check_hresult(hr);

	if (!merge) {
		return EXIT_SUCCESS;
	}

	auto ktcPath = wil::ExpandEnvironmentStrings(L"%ProgramFiles(x86)%\\Windows Kits\\10\\Windows Performance Toolkit\\KernelTraceControl.dll");
	wil::unique_hmodule ktc;
	ktc.reset(LoadLibrary(ktcPath.get()));
	if (!ktc) {
		ktc.reset(LoadLibraryEx(L"KernelTraceControl.dll", nullptr, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS));
		if (!ktc) {
			fwprintf(stderr, L"Failed loading KernelTraceControl.dll.\n");
			return EXIT_FAILURE;
		}
	}

	auto cmtf = reinterpret_cast<decltype(&CreateMergedTraceFile)>(GetProcAddress(ktc.get(), "CreateMergedTraceFile"));
	if (!cmtf) {
		fwprintf(stderr, L"CreateMergedTraceFile not found in KernelTraceControl.dll.\n");
		return EXIT_FAILURE;
	}

	
	LPCWSTR mergedFiles[] = { wideOutputFileName.c_str() };
	if (compress) {
		extendedDataFlags |= EVENT_TRACE_MERGE_EXTENDED_DATA_COMPRESS_TRACE;
	}

	std::wstring wideMergedFileName = widen(mergedFileName);
	ULONG result = cmtf(wideMergedFileName.c_str(),
		mergedFiles,
		_countof(mergedFiles),
		extendedDataFlags);
	if (result != ERROR_SUCCESS) {
		fwprintf(stderr, L"CreateMergedTraceFile failed with error 0x%08x.\n", result);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
