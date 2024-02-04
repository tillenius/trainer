#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <Windows.h>

struct AutoCloseHandle {
    AutoCloseHandle(HANDLE handle) : m_handle(handle) {}
    ~AutoCloseHandle() {
        CloseHandle(m_handle);
    }
    HANDLE m_handle;
};

struct Region {
    char *      addr;
    uint64_t    size;
    bool        good;
};

struct Match {
    char *      addr;
    char        data[8];
};

std::vector<char> g_buffer;

class Search {
public:
    Search(HANDLE handle, std::vector<Region> & regions) : m_handle(handle), m_regions(regions) {}

    template<typename Pred>
    void NewSearch(int size, Pred predicate) {
        m_matches.clear();
        for (int i = 0; i < m_regions.size(); ++i) {
            if (!m_regions[i].good) {
                continue;
            }
            if (!ReadProcessMemory(m_handle, m_regions[i].addr, g_buffer.data(), m_regions[i].size, NULL)) {
                m_regions[i].good = false;
                continue;
            }
            for (int j = 0; j < m_regions[i].size; j += size) {
                if (predicate(&g_buffer[j])) {
                    Match match = { 0 };
                    match.addr = &m_regions[i].addr[j];
                    memcpy(match.data, &g_buffer[j], size);
                    m_matches.push_back(match);
                }
            }
        }
        DumpResults();
    }

    template<typename Pred>
    void Refine(int size, Pred predicate) {
        int iMatch = 0;
        std::vector<Match> newMatches;
        for (int i = 0; iMatch < m_matches.size() && i < m_regions.size(); ++i) {
            if (!m_regions[i].good) {
                continue;
            }
            while (m_matches[iMatch].addr < m_regions[i].addr && iMatch < m_matches.size()) {
                ++iMatch;
            }
            char * maxAddr = (char *) m_regions[i].addr + m_regions[i].size;
            if (maxAddr < m_matches[iMatch].addr) {
                continue;
            }
            if (!ReadProcessMemory(m_handle, m_regions[i].addr, g_buffer.data(), m_regions[i].size, NULL)) {
                m_regions[i].good = false;
                continue;
            }
            for (; iMatch < m_matches.size() && m_matches[iMatch].addr < maxAddr; ++iMatch) {
                ptrdiff_t localAddr = (ptrdiff_t) ( m_matches[iMatch].addr - m_regions[i].addr );
                if (predicate(m_matches[iMatch], &g_buffer[localAddr])) {
                    Match match = { 0 };
                    match.addr = m_matches[iMatch].addr;
                    memcpy(match.data, &g_buffer[localAddr], size);
                    newMatches.push_back(match);
                }
            }
        }
        m_matches.swap(newMatches);
        DumpResults();
    }

    void DumpResults() {
        std::cout << "Results: " << std::dec << m_matches.size() << std::hex << std::endl;
        if (m_matches.size() < 15 ) {
            for (size_t i = 0; i < m_matches.size(); ++i) {
                std::cout << (uint64_t) m_matches[i].addr << " ";
                for (int j = 0; j < 8; ++j) {
                    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) m_matches[i].data[j] << " ";
                }
                std::cout << std::endl;
            }
        }
    }

    HANDLE m_handle;
    std::vector<Region> & m_regions;
    std::vector<Match> m_matches;
};

void ScanRegions(HANDLE handle, std::vector<Region> & regions) {
    MEMORY_BASIC_INFORMATION info;
    SIZE_T maxSize = 0;
    for (LPCVOID addr = 0;; addr = (char *) addr + info.RegionSize) {
        if (!VirtualQueryEx(handle, addr, &info, sizeof(info))) {
            g_buffer.resize(maxSize);
            return;
        }
        if (info.State != MEM_COMMIT) {
            continue;
        }
        if ((info.Protect & PAGE_READWRITE) == 0) {
            continue;
        }
        regions.push_back(Region{ (char *) info.BaseAddress, info.RegionSize, true});
        if (info.RegionSize > maxSize) {
            maxSize = info.RegionSize;
        }
    }
}

std::vector<std::string> split(const std::string & s) {
    std::vector<std::string> res;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ' ')) {
        if (!token.empty()) {
            res.push_back(token);
        }
    }
    return res;
}

int main() {
    HWND hwnd = FindWindow(L"UnityWndClass", NULL);
    if (hwnd == NULL) {
        std::cout << "FindWindow failed." << std::endl;
        return 0;
    }

    DWORD procID;
    GetWindowThreadProcessId(hwnd, &procID);
    if (procID == NULL) {
        std::cout << "GetWindowThreadProcessId failed" << std::endl;
        return 0;
    }
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (handle == NULL) {
        std::cout << "OpenProcess failed" << std::endl;
        return 0;
    }
    AutoCloseHandle _handle(handle);

    std::vector<Region> regions;
    ScanRegions(handle, regions);

    std::cout << std::hex;

    std::string text;
    
    Search search(handle, regions);
    for (;;) {
        std::cout << ">>> ";
        if (!std::getline(std::cin, text)) {
            break;
        }
        if (text=="") {
            continue;
        }
        if (text=="q") {
            break;
        }

        std::vector<std::string> words = split(text);
        if (words.size() < 2) {
            continue;
        }

        // start new search
        if (words[0] == "s1") {
            uint8_t val = atoi(words[1].c_str());
            search.NewSearch(1, [val](void * ptr) { return *(uint8_t *) ptr == val; });
            continue;
        }
        if (words[0] == "s2") {
            WORD val = atoi(words[1].c_str());
            search.NewSearch(sizeof(WORD), [val](void * ptr) { return *(WORD *) ptr == val; });
            continue;
        }
        if (words[0] == "s4") {
            DWORD val = atoi(words[1].c_str());
            search.NewSearch(sizeof(DWORD), [val](void * ptr) { return *(DWORD *) ptr == val; });
            continue;
        }
        if (words[0] == "sf4") {
            float val = (float) atof(words[1].c_str());
            search.NewSearch(sizeof(float), [val](void * ptr) { return fabs(*(float *) ptr - val) < 2.0f; });
            continue;
        }
        if (words[0] == "sf8") {
            double val = atof(words[1].c_str());
            search.NewSearch(sizeof(double), [val](void * ptr) { return fabs(*(double *) ptr - val) < 2.0; });
            continue;
        }

        // refine results
        if (words[0] == "c1") {
            uint8_t val = atoi(words[1].c_str());
            search.Refine(1, [val](Match & m, void * ptr) { return *(uint8_t *) ptr == val; });
            continue;
        }
        if (words[0] == "c2") {
            WORD val = atoi(words[1].c_str());
            search.Refine(sizeof(WORD), [val](Match & m, void * ptr) { return *(WORD *) ptr == val; });
            continue;
        }
        if (words[0] == "c4") {
            DWORD val = atoi(words[1].c_str());
            search.Refine(sizeof(DWORD), [val](Match & m, void * ptr) { return *(DWORD *) ptr == val; });
            continue;
        }
        if (words[0] == "cf4") {
            if (words[1] == "<") {
                search.Refine(sizeof(float), [](Match & m, void * ptr) { return *(float *) ptr < *(float *) m.data; });
            } else if (words[1] == ">") {
                search.Refine(sizeof(float), [](Match & m, void * ptr) { return *(float *) ptr > *(float *) m.data; });
            } else {
                float val = (float) atof(words[1].c_str());
                search.Refine(sizeof(float), [val](Match & m, void * ptr) { return fabs(*(float *) ptr - val) < 2.0f; });
            }
            continue;
        }
        if (words[0] == "cf8") {
            if (words[1] == "<") {
                search.Refine(sizeof(double), [](Match & m, void * ptr) { return *(double *) ptr < *(double *) m.data; });
            } else if (words[1] == ">") {
                search.Refine(sizeof(double), [](Match & m, void * ptr) { return *(double *) ptr > *(double *) m.data; });
            } else {
                double val = atof(words[1].c_str());
                search.Refine(sizeof(double), [val](Match & m, void * ptr) { return fabs(*(double *) ptr - val) < 2.0f; });
            }
            continue;
        }

        if (words[0] == "w") {
            if (words.size() == 3) {
                uint64_t addr = strtoull(words[1].c_str(), nullptr, 16);
                WORD data = atoi(words[2].c_str());
                std::cout << "write " << std::hex << addr << " = " << std::dec << data << std::hex << std::endl;
                if (!WriteProcessMemory(handle, (void *) addr, &data, sizeof(WORD), NULL)) {
                    std::cout << "write failed" << std::endl;
                } else {
                    std::cout << "write success" << std::endl;
                }
            }
        }
        if (text[0] == 'x') {
            if (words.size() == 3) {
                uint64_t addr = strtoull(words[1].c_str(), nullptr, 16);
                WORD data = atoi(words[2].c_str());

                WORD key = 0;
                if (!ReadProcessMemory(handle, (void *) (addr-12), &key, sizeof(WORD), NULL)) {
                    std::cout << "read failed" << std::endl;
                }
                std::cout << "key: " << std::hex << std::setfill('0') << std::setw(4) << key << std::endl;
                if (!WriteProcessMemory(handle, (void *) addr, &data, sizeof(WORD), NULL)) {
                    std::cout << "write failed" << std::endl;
                } else {
                    std::cout << "write " << std::hex << addr << " = " << std::dec << data << std::hex << std::endl;
                }
                addr = addr - 8;
                data = key^data;
                if (!WriteProcessMemory(handle, (void *) addr, &data, sizeof(WORD), NULL)) {
                    std::cout << "write failed" << std::endl;
                } else {
                    std::cout << "write " << std::hex << addr << " = " << std::dec << data << std::hex << std::endl;
                }
            }
        }
        if (text[0] == 'r') {
            uint64_t addr = strtoull(words[1].c_str(), nullptr, 16);
            WORD data;
            if (!ReadProcessMemory(handle, (void *) addr, &data, sizeof(WORD), NULL)) {
                std::cout << "read failed" << std::endl;
            } else {
                std::cout << "read " << std::hex << addr << " = " << std::dec << data << std::hex << std::endl;
            }
        }
        if (text[0] == 'd') {
            uint64_t addr = strtoull(words[1].c_str(), nullptr, 16);
            char data[16];
            std::cout << std::setfill('0') << std::setw(2);
            if (!ReadProcessMemory(handle, (void *) addr, &data, sizeof(data), NULL)) {
                std::cout << "read failed" << std::endl;
            } else {
                for (int i = 0; i < sizeof(data); ++i) {
                    std::cout << std::setfill('0') << std::setw(2) << (int) (uint8_t) data[i] << " ";
                }
                for (int i = 0; i < sizeof(data); ++i) {
                    if (std::isprint((uint8_t) data[i])) {
                        std::cout << data[i];
                    } else {
                        std::cout << ".";
                    }
                }
                std::cout << "\n";
            }
        }
    }

    std::cout << "done." << std::endl;
    return 0;
}
