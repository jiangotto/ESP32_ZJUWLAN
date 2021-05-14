/*
 * 
 * zjunet.h
 * 
 *  This file is used to connect to ZJUWLAN.
 * 
 * History:
 *          - first release, 
 *            April 27, 2021, Otto Jiang
 *            
 */

#include <WiFiClientSecure.h>
#include <WiFi.h>
#include "Regexp.h"
#include "Array.h"
#include "MD5.h"
#include "Hash.h"

// DEFINITIONS - change according to your needs

String USERNAME = "yourUsername";
String PASSWORD = "yourPassword";

const int httpsPort = 443;
String HTTPS = "";
String INIT_URL = "net2.zju.edu.cn";
String GET_CHALLENGE_API = "/cgi-bin/get_challenge";
String SRUN_PORTAL_API = "/cgi-bin/srun_portal";
String N = "200";
String TYPE = "1";
String ENC = "srun_bx1";
String _PADCHAR = "=";
String _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

String ip = "";
String ac_id = "3";
String randnum = "";
String token = "";
String request = "";
String res = "";
String i = "";
String hmd5 = "";
String chksum = "";
String t;

const int ELEMENT_COUNT_MAX = 50;

WiFiClientSecure ZJUNET;
MatchState ms;

// FUNCTIONS OF THIS MODULE

int zjunet (void);

Array<uint32_t, 4 * ELEMENT_COUNT_MAX> xencode(String msg, String key);
Array<uint32_t,ELEMENT_COUNT_MAX> sencode(String msg, bool key);
Array<uint32_t, 4 * ELEMENT_COUNT_MAX> lencode(Array<uint32_t,ELEMENT_COUNT_MAX> msg, bool key);
int ordat(String msg, int idx);
String base64(Array<uint32_t, 4 * ELEMENT_COUNT_MAX> s);
String md5(String password, String token);
String get_chksum(void);
String trans(String msg);

// VARIABLES AND FUNCTIONS TO BE USED INSIDE THIS MODULE

int zjunet (void)
{
    Serial.begin(115200);

    randomSeed(123);
    randnum = (String)abs(random(1234567890123456789012));
    Serial.println(randnum);
    
    WiFi.begin("ZJUWLAN","");
    while (WiFi.status() != WL_CONNECTED) 
    {
        Serial.print(".");
        // wait 1 second for re-trying
        delay(1000);
    }
    Serial.println("");

    ip = WiFi.localIP().toString();
    Serial.println(ip);

    if(!ZJUNET.connect((char*)(INIT_URL.c_str()), httpsPort))
        return 0;

    request = "GET " + 
            HTTPS + GET_CHALLENGE_API + "?" + 
            "callback=jQuery" + randnum + 
            "_" + "1620964023000"/*(String)time(NULL)*/ + "&" +
            "username=" + USERNAME + "&" +
            "ip=" + "1620964023000" + "&" +
            "_=" + t/*(String)time(NULL)*/ + 
            " HTTP/1.1\r\n" +
            "Host: " + INIT_URL + "\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4492.0 Safari/537.36 Edg/92.0.881.0\r\n" +
            "Referer: https://net2.zju.edu.cn/srun_portal_pc?ac_id=3&theme=zju" +
            "Connection: keep-alive\r\n" +
            "\r\n";
    ZJUNET.print(request);
    Serial.println(request);
    res = "";
    while (ZJUNET.connected()) 
    {
      String line = ZJUNET.readStringUntil('\n');
      if (line == "\r")
        break;
    }
    while (ZJUNET.available()) 
    {
      char c = ZJUNET.read();
      res += (String)c;
    }

    Serial.println(res);

    ms.Target((char*)(res.c_str()),res.length());
    char Token[res.length()];
    char T[res.length()];
    if(ms.Match("\"challenge\":\"(.*)\",\"client_ip\"") == REGEXP_MATCHED)
        ms.GetCapture(Token,0);
    if(ms.Match("\"st\":(.*)}") == REGEXP_MATCHED)
        ms.GetCapture(T,0);

    token = String(Token);
    t = String(T) + "000";
    Serial.println(token);
    Serial.println(t);

    i = "{\"username\":\"" + USERNAME + "\"," +
        "\"password\":\"" + PASSWORD + "\"," +
        "\"ip\":\"" + ip + "\"," +
        "\"acid\":\"" + ac_id + "\"," +
        "\"enc_ver\":\"" + ENC + "\"}";
    Serial.println(i);
    i = "{SRBX1}" + base64(xencode(i, token));
    Serial.println(i);
    hmd5 = md5(PASSWORD, token);
    Serial.println(hmd5);
    chksum = sha1(get_chksum());
    Serial.println(chksum);

    ZJUNET.stop();
    if(!ZJUNET.connect((char*)(INIT_URL.c_str()), httpsPort))
        return 0;

    request = "GET " + 
            HTTPS + SRUN_PORTAL_API + "?" + 
            "callback=jQuery" + randnum + 
            "_" + t/*(String)time(NULL)*/ + "&" +
            "action=login" + "&" +
            "username=" + USERNAME + "&" +
            "password=%7BMD5%7D" + trans(hmd5) + "&" +
            "ac_id=" + ac_id + "&" +
            "ip=" + ip + "&" +
            "chksum=" + chksum + "&" +
            "info=" + trans(i) + "&" +
            "n=" + N + "&" +
            "type=" + TYPE + "&" +
            "os=windows+10" + "&" +
            "name=windows" + "&" +
            "double_stack=0" + "&" +
            "_=" + t/*(String)time(NULL)*/ + 
            " HTTP/1.1\r\n" +
            "Host: " + INIT_URL + "\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4492.0 Safari/537.36 Edg/92.0.881.0\r\n" +
            "Referer: https://net2.zju.edu.cn/srun_portal_pc?ac_id=3&theme=zju" +
            "Connection: keep-alive\r\n" +
            "\r\n";
    ZJUNET.print(request);
    Serial.println(request);
    
    res = "";
    while (ZJUNET.connected()) 
    {
      String line = ZJUNET.readStringUntil('\n');
      if (line == "\r")
        break;
    }
    while (ZJUNET.available()) 
    {
      char c = ZJUNET.read();
      res += (String)c;
    }

    Serial.println(res);

    ms.Target((char*)(res.c_str()),res.length());
    if(ms.Match("E0000") == REGEXP_MATCHED)
        return 1;
    else 
        return 0;
}

Array<uint32_t,4 * ELEMENT_COUNT_MAX> xencode(String msg, String key)
{
    if(msg == "")
        return 0;
    Array<uint32_t,ELEMENT_COUNT_MAX> pwd = sencode(msg, true);
    Array<uint32_t,ELEMENT_COUNT_MAX> pwdk = sencode(key, false);
    //for(int i = 0;i<pwd.size();i++)
    //    {Serial.print(pwd[i]);Serial.print(", ");}
    //Serial.println("");
    //for(int i = 0;i<pwdk.size();i++)
    //    {Serial.print(pwdk[i]);Serial.print(", ");}
    //Serial.println("");
    
    int lpwdk = pwdk.size();
    if(lpwdk < 4)
        for(int i = 0;i < (4 - lpwdk);i++)
            pwdk.push_back(0);
    uint64_t n = pwd.size() - 1;
    uint64_t z = pwd[n];
    uint64_t c = 0x86014019 | 0x183639A0;
    uint64_t q = floor(6 + 52 / (n + 1));
    uint64_t d = 0;
    while(q > 0)
    {
        d += c & (uint64_t)(0x8CE0D9BF | 0x731F2640);
        //Serial << "d: " << d << endl;
        uint64_t e = d >> 2 & 3;
        //Serial << "e: " << e << endl;
        uint64_t p = 0;
        while(p < n)
        {
            uint64_t y = pwd[p + 1];
            //Serial << "y: " << y << endl;
            uint64_t m = z >> 5 ^ y << 2;
            //Serial << "m0: " << m << endl;
            m += ((y >> 3 ^ z << 4) ^ (d ^ y));
            //Serial << "m1: " << m << endl;
            m += (pwdk[(p & 3) ^ e] ^ z);
            //Serial << "m2: " << m << endl;
            pwd[p] += m & (uint64_t)(0xEFB8D130 | 0x10472ECF);
            z = pwd[p];
            //Serial.print(pwd[p]);
            //Serial.println(", ");
            p = p + 1;
        }
        uint64_t y = pwd[0];
        uint64_t m = z >> 5 ^ y << 2;
        m += ((y >> 3 ^ z << 4) ^ (d ^ y));
        m += (pwdk[(p & 3) ^ e] ^ z);
        pwd[n] += m & (uint64_t)(0xBB390742 | 0x44C6F8BD);
        z = pwd[n];
        q = q - 1;
        //Serial.println(pwd[n]);
    }
    return lencode(pwd, false);
}

Array<uint32_t,ELEMENT_COUNT_MAX> sencode(String msg, bool key)
{
    int l = msg.length();
    Array<uint32_t,ELEMENT_COUNT_MAX> pwd;
    for(int i = 0;i < l;i += 4)
        pwd.push_back(ordat(msg, i) | 
        ordat(msg, i + 1) << 8 | 
        ordat(msg, i + 2) << 16 | 
        ordat(msg, i + 3) << 24);
    if(key)
        pwd.push_back(l);
    return pwd;
}

Array<uint32_t, 4 * ELEMENT_COUNT_MAX> lencode(Array<uint32_t,ELEMENT_COUNT_MAX> msg, bool key)
{
    int l = msg.size();
    Array<uint32_t, 4 * ELEMENT_COUNT_MAX> res;
    int ll = (l - 1) << 2;
    if(key){/*not used*/}
    for(int i = 0;i < l;i++)
    {
        res.push_back(msg[i] & 0xff);
        res.push_back(msg[i] >> 8 & 0xff);
        res.push_back(msg[i] >> 16 & 0xff);
        res.push_back(msg[i] >> 24 & 0xff);
    }
    if(key){/*not used*/}
    return res;
}

int ordat(String msg, int idx)
{
    if(msg.length() > idx)
		return (int)(msg[idx]);
	return 0;
}

String base64(Array<uint32_t, 4 * ELEMENT_COUNT_MAX> s)
{
    String x = "";
    int imax = s.size() - s.size() % 3;
    if(s.size() == 0)
        return "";
    for(int i = 0;i < imax;i += 3)
    {
        uint32_t b10 = s[i] << 16 | s[i + 1] << 8 | s[i + 2];
        x += (_ALPHA[(b10 >> 18)]);
        x += (_ALPHA[((b10 >> 12) & 63)]);
        x += (_ALPHA[((b10 >> 6) & 63)]);
        x += (_ALPHA[(b10 & 63)]);
    }
    int i = imax;
    if((s.size() - imax) == 1)
    {
        uint32_t b10 = s[i] << 16;
        x += _ALPHA[(b10 >> 18)];
        x += _ALPHA[((b10 >> 12) & 63)];
        x += _PADCHAR;
        x += _PADCHAR;
    }
    else if((s.size() - imax) == 2)
    {
        uint32_t b10 = s[i] << 16 | s[i + 1] << 8;
        x += _ALPHA[(b10 >> 18)];
        x += _ALPHA[((b10 >> 12) & 63)];
        x += _ALPHA[((b10 >> 6) & 63)];
        x += _PADCHAR;
    }
    return x;
}

String md5(String PASSWORD, String token)
{
    MD5  hashMD5;
    String res = hashMD5.hmac_md5((char *)(PASSWORD.c_str()), PASSWORD.length(), (char *)(token.c_str()), token.length());
    return res;
}

String get_chksum(void)
{
    String chkstr = "";
    chkstr += token + USERNAME;
    chkstr += token + hmd5;
    chkstr += token + ac_id;
    chkstr += token + ip;
    chkstr += token + N;
    chkstr += token + TYPE;
    chkstr += token + i;
    return chkstr;
}

String trans(String msg)
{
    int len = msg.length();
    String res = "";
    for(int i = 0;i < len;i++)
    {
        if(msg[i] == '+')
            res += "%2B";
        else if(msg[i] == '/')
            res += "%2F";
        else if(msg[i] == '=')
            res += "%3D";
        else if(msg[i] == '{')
            res += "%7B";
        else if(msg[i] == '}')
            res += "%7D";
        else
            res += String(msg[i]);
    }
    return res;
}
