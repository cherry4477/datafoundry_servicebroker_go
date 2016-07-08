package daas

import (
	"fmt"
	"errors"
	"time"
	//"strings"
	"bytes"
	//"bufio"
	//"io"
	//"os"
	"io/ioutil"
	"crypto/tls"
	"net/http"
	//neturl "net/url"
	"encoding/base64"
	"encoding/base32"
	"encoding/json"
	"encoding/hex"
	"crypto/md5"
)

//==============================================================
// 
//==============================================================

func init() {
}

func getMd5(content string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(content))
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

//==============================================================
// 
//==============================================================

type OracleDaasClient struct {
	host string
	
	identityDomainId string
	
	username string
	password string
	token    string
}

func newOracleDaasClient(host, username, password, identityDomainId string) *OracleDaasClient {
	host = "https://" + host
	odc := &OracleDaasClient{
		host: host,
		
		identityDomainId: identityDomainId,
		
		username: username,
		password: password,
	}
	
	odc.token = getMd5(fmt.Sprintf("Basic %s:%s", username, password))
	
	return odc
}

func (odc *OracleDaasClient) request (method string, url string, body []byte, timeout time.Duration) (*http.Response, error) {
	var req *http.Request
	var err error
	if len(body) == 0 {
		req, err = http.NewRequest(method, url, nil)
	} else {
		req, err = http.NewRequest(method, url, bytes.NewReader(body))
	}
	
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ID-TENANT-NAME", odc.identityDomainId)
	req.Header.Set("Authorization", odc.token)
	
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transCfg,
		Timeout: timeout,
	}
	return client.Do(req)
}

const GeneralRequestTimeout = time.Duration(30) * time.Second

type OracleDaasREST struct {
	c  *OracleDaasClient
	E error
}

func NewOracleDaasREST(odc *OracleDaasClient) *OracleDaasREST {
	return &OracleDaasREST{c: odc}
}

func (odr *OracleDaasREST) doRequest (method, url string, bodyParams interface{}, into interface{}) *OracleDaasREST {
	if odr.E != nil {
		return odr
	}
	
	var body []byte
	if bodyParams != nil {
		body, odr.E = json.Marshal(bodyParams)
		if odr.E != nil {
			return odr
		}
	}
	
	//res, odr.E := odc.request(method, url, body, GeneralRequestTimeout) // non-name error
	res, err := odr.c.request(method, url, body, GeneralRequestTimeout)
	odr.E = err
	if odr.E != nil {
		return odr
	}
	defer res.Body.Close()
	
	var data []byte
	data, odr.E = ioutil.ReadAll(res.Body)
	if odr.E != nil {
		return odr
	}
	
	//println("22222 len(data) = ", len(data), " , res.StatusCode = ", res.StatusCode)
	
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		odr.E = errors.New(string(data))
	} else {
		if into != nil {
			//println("into data = ", string(data), "\n")
		
			odr.E = json.Unmarshal(data, into)
		}
	}
	
	return odr
}

func (odr *OracleDaasREST) Get (uri string, into interface{}) *OracleDaasREST {
	return odr.doRequest("GET", odr.c.host + uri, nil, into)
}

func (odr *OracleDaasREST) Delete (uri string, into interface{}) *OracleDaasREST {
	return odr.doRequest("DELETE", odr.c.host + uri, nil, into)
}

func (odr *OracleDaasREST) Post (uri string, body interface{}, into interface{}) *OracleDaasREST {
	return odr.doRequest("POST", odr.c.host + uri, body, into)
}

func (odr *OracleDaasREST)OPut (uri string, body interface{}, into interface{}) *OracleDaasREST {
	return odr.doRequest("PUT", odr.c.host + uri, body, into)
}

//===============================================================
// 
//===============================================================

func NewElevenLengthID() string {
	t := time.Now().UnixNano()
	bs := make([]byte, 8)
	for i := uint(0); i < 8; i ++ {
		bs[i] = byte((t >> i) & 0xff)
	}
	return string(base64.RawURLEncoding.EncodeToString(bs))
}

var base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
func NewThirteenLengthID() string {
	t := time.Now().UnixNano()
	bs := make([]byte, 8)
	for i := uint(0); i < 8; i ++ {
		bs[i] = byte((t >> i) & 0xff)
	}
	
	dest := make([]byte, 16)
	base32Encoding.Encode(dest, bs)
	return string(dest[:13])
}


