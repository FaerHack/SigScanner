#include <iostream>
#include <fstream>
#include <Windows.h>
#include <filesystem>
#include <map>
#include <shared_mutex>
#include <functional>
#include <execution>
#include <set>

#define IS_BACKED_BY_RANGE(BaseAddress, Size, Address) ((Address) >= (BaseAddress) && (Address) < ((BaseAddress) + (Size)))
#define MIN_SIG_LEN 12
#define ROUND_TO(Val, Align)  (((ULONG64)(Val) + Align - 1) & ~((ULONG64)Align - 1))

PBYTE Buff1 = 0;
PBYTE Buff2 = 0;

PIMAGE_SECTION_HEADER pISH1 = 0;
PIMAGE_SECTION_HEADER pISH2 = 0;

std::vector<SIGNATURE>Signatures;
std::shared_mutex mtSignatures;

PVOID FileLoadToMemory(
	_In_ std::wstring FilePath,
	_Out_opt_ size_t* lpcbFile)
{
	std::ifstream InputFile(FilePath, std::ios::in | std::ios::binary);
	if (!InputFile.is_open())
		return nullptr;

	auto cbFile = std::filesystem::file_size(FilePath);
	auto pbFile = new BYTE[cbFile];
	if (!pbFile)
		return nullptr;

	InputFile.read(reinterpret_cast<char*>(pbFile), cbFile);

	if (lpcbFile)
		*lpcbFile = cbFile;

	return pbFile;
}

ULONG64 PETranslateRawToVirtualAddress(
	_In_ PBYTE Image,
	_In_ ULONG64 RRA)
{
	const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS64>(Image + reinterpret_cast<PIMAGE_DOS_HEADER>(Image)->e_lfanew);

	auto Section = IMAGE_FIRST_SECTION(pINH);

	for (size_t i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (IS_BACKED_BY_RANGE(Section[i].PointerToRawData, Section[i].SizeOfRawData, RRA))
		{
			auto SectionOffset = RRA - Section[i].PointerToRawData;
			if (SectionOffset >= Section[i].Misc.VirtualSize)
				return 0;

			return pINH->OptionalHeader.ImageBase + Section[i].VirtualAddress + SectionOffset;
		}
	}

	return 0;
}

std::string SignatureToString(
	_In_ PBYTE Buff,
	_In_ UINT Len)
{
	std::stringstream SS;

	for (size_t i = 0; i < Len; ++i)
	{
		SS << std::setfill('0') << std::setw(2) << std::hex << static_cast<size_t>(reinterpret_cast<PUCHAR>(Buff)[i]);

		if (i != Len - 1)
			SS << ' ';
	}

	return SS.str();
}

struct SIGNATURE
{
	ULONG Offset1;
	ULONG Offset2;
	ULONG Size;

	bool operator<(const SIGNATURE& Other) const
	{
		return Offset1 < Other.Offset1 && Offset2 < Other.Offset2;
	}
};

struct SIGNATURE_INFO
{
	std::string Signature;
	std::vector<std::pair<ULONG64, ULONG64>>Matches;

	bool operator==(const std::string& Other) const
	{
		return Signature == Other;
	}
};

int CountSignature(int Start, int k)
{
	int matches = 0;

	int garbage = 0;

	int current = Start;

	for (size_t i = k; i < pISH2->SizeOfRawData && current < pISH1->SizeOfRawData; i++, current++)
	{
		auto v1 = Buff1[current];
		auto v2 = Buff2[i];

		if (v1 == v2)
		{
			if ((v1 == 0x0 || v1 == 0xCC || v1 == 0x90) && current > Start)
			{
				auto prev = Buff1[current - 1];
				if (prev == v1)
				{
					garbage++;
				}

				if (garbage > 4)
					break;
			}
			else
			{
				garbage = 1;
			}

			matches++;
		}
		else
		{
			break;
		}
	}

	return matches;
}

void ScanBlock(int Start, int Batch, int* State)
{
	for (size_t Offset = 0; Offset < Batch; Offset++)
	{
		for (size_t k = 0; k < pISH2->SizeOfRawData && k < pISH1->SizeOfRawData; k++)
		{
			auto Iter = Start + Offset;

			if (Buff1[Iter] == Buff2[k])
			{
				auto Matches = CountSignature(Iter, k);

				if (Matches < MIN_SIG_LEN)
					continue;

				mtSignatures.lock_shared();

				SIGNATURE Signature{ pISH1->PointerToRawData + Iter, pISH2->PointerToRawData + k, Matches };
				auto FoundSig = std::find_if(Signatures.begin(), Signatures.end(), [&](const SIGNATURE& Other)
					{
						return (Signature.Offset1 + Signature.Size) == (Other.Offset1 + Other.Size) || (Signature.Offset2 + Signature.Size) == (Other.Offset2 + Other.Size);
					});

				mtSignatures.unlock_shared();

				if (FoundSig != Signatures.end())
				{
					continue;
				}

				mtSignatures.lock();
				Signatures.push_back(Signature);
				mtSignatures.unlock();
			}
		}

		*State = Offset;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	if(argc != 3)
	{
		std::cout << "Usage: <first file path> <second file path>" << std::endl;
		return 1;
	}

	size_t cbFile1;
	size_t cbFile2;

	auto pFile1 = (PBYTE)FileLoadToMemory(std::wstring(argv[1]), &cbFile1);
	auto pFile2 = (PBYTE)FileLoadToMemory(std::wstring(argv[2]), &cbFile2);

	auto pINH1 = (PIMAGE_NT_HEADERS)(pFile1 + ((PIMAGE_DOS_HEADER)pFile1)->e_lfanew);
	auto pINH2 = (PIMAGE_NT_HEADERS)(pFile2 + ((PIMAGE_DOS_HEADER)pFile2)->e_lfanew);

	if (!std::filesystem::exists("Results"))
		std::filesystem::create_directory("Results");

	tm Time;
	auto Now = time(nullptr);
	localtime_s(&Time, &Now);
	std::ofstream OutputFile(std::format("Results/{}_{}_{} {}_{}_{}.txt", Time.tm_mday, Time.tm_mon + 1, Time.tm_year + 1900, Time.tm_hour, Time.tm_min, Time.tm_sec), std::ofstream::binary);

	auto NumberThreads = std::thread::hardware_concurrency();

	for (size_t i = 0; i < pINH1->FileHeader.NumberOfSections; i++)
	{
		pISH1 = &IMAGE_FIRST_SECTION(pINH1)[i];
		pISH2 = &IMAGE_FIRST_SECTION(pINH2)[i];

		Buff1 = pFile1 + pISH1->PointerToRawData;
		Buff2 = pFile2 + pISH2->PointerToRawData;

		std::cout << "Scanning section: " << pISH1->Name << std::endl;

		size_t Offset = 0;
		size_t Batch = pISH1->SizeOfRawData / NumberThreads;

		std::vector<std::thread>Threads;

		auto State = std::make_unique<int[]>(NumberThreads);

		auto Start = std::chrono::high_resolution_clock::now();

		for (size_t Proc = 0; Proc < NumberThreads; Proc++)
		{
			Threads.emplace_back(ScanBlock, Offset, Batch, &State[Proc]);
			Offset += Batch;
		}

		int PrevState = 0;
		for (size_t j = 0; j < NumberThreads; j++)
		{
			auto hThread = Threads[j].native_handle();
			while (true)
			{
				if (WaitForSingleObject(hThread, 200) == WAIT_OBJECT_0)
					break;

				if (PrevState < State[j])
				{
					printf("Completed %.2f\n", ((float)State[j] / (float)Batch) * 100.f);
					PrevState = State[j];
				}
			}

			Threads[j].detach();
		}

		auto End = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double> Duration(End - Start);
		printf("Scanning took %.3fms\n", Duration.count() * 1000.0);

		if (!Signatures.size())
			continue;

		std::vector<SIGNATURE_INFO>SignaturesSorted;

		std::sort(Signatures.begin(), Signatures.end());

		for (auto& Signature : Signatures)
		{
			auto SignatureStr = SignatureToString(pFile1 + Signature.Offset1, Signature.Size);
			auto SignatureInfo = std::find(SignaturesSorted.begin(), SignaturesSorted.end(), SignatureStr);
			if (SignatureInfo != SignaturesSorted.end())
				SignatureInfo->Matches.emplace_back(Signature.Offset1, Signature.Offset2);
			else
				SignaturesSorted.push_back({ SignatureStr, {std::make_pair(Signature.Offset1, Signature.Offset2) }});
		}

		OutputFile << "Signatures in \"" << pISH1->Name << "\" (" << SignaturesSorted.size() << "):" << std::endl;

		size_t SignatureIndex = 0;
		for (auto& Signature : SignaturesSorted)
		{
			OutputFile << std::format("\t [{}] {} (Size: {}, Matches: {})\n", SignatureIndex, Signature.Signature, (Signature.Signature.length() + 1) / 3, Signature.Matches.size());

			for (auto& Match : Signature.Matches)
				OutputFile << std::format("\t\t 0x{:X} == 0x{:X} (0x{:X} == 0x{:X})\n", PETranslateRawToVirtualAddress(pFile1, Match.first), PETranslateRawToVirtualAddress(pFile2, Match.second), Match.first, Match.second);

			SignatureIndex++;
		}

		OutputFile.flush();

		Signatures.clear();
	}
}