package main

/*
References:
- https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
- https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/reg.rb
- https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
- https://github.com/Velocidex/regparser/blob/bbc758cbd18b/regparser_gen.go
- https://www.rapid7.com/blog/post/2012/01/16/adventures-in-the-windows-nt-registry-a-step-into-the-world-of-forensics-and-ig/
- https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
- https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_LOCAL_MACHINE/SAM/SAM/Domains/Account/Users/000001F4/index
- https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
*/

import (
    "fmt"
    "www.velocidex.com/golang/regparser"
    "os"
    "flag"
    "time"
    "io"
    "encoding/binary"
    "strings"
    "encoding/hex"
)

func ParseInt32(reader io.ReaderAt, offset int64) (integer int32, err error) {
    data := make([]byte, 4)
    _, err = reader.ReadAt(data, offset)
    if err != nil {
       return 0, err
    }

    return int32(binary.LittleEndian.Uint32(data)), nil
}

/*
Adapted from here:
https://github.com/Velocidex/regparser/blob/bbc758cbd18bc960a389efef2274a14181b7cdf5/helpers.go
*/
func UTF16LEBytesToUTF8(utf16Bytes []byte) string {
    if len(utf16Bytes) < 2 {
        return ""
    }

    utf8Bytes := make([]byte, (len(utf16Bytes) / 2))

    for i, _ := range utf8Bytes {
        utf8Bytes[i] = utf16Bytes[i * 2]
    }

    return string(utf8Bytes)
}

func RetrieveBootKeyPart(parser regparser.Registry, keyName string) (keyPart string, err error) {
    keyPath := fmt.Sprintf("\\ControlSet001\\Control\\Lsa\\%s", keyName)
    key := parser.OpenKey(keyPath)

    if key == nil {
        fmt.Printf("[!] Error opening key '%s'\n", keyPath)
        return "", nil
    }

    var hiveCellOffset int64
    hiveCellOffset = 4096 + int64(key.Class())
    hiveCell := parser.Profile.HCELL(parser.Reader, hiveCellOffset)

    // should be "hbin" in little-endian
    offset, err := ParseInt32(hiveCell.Reader, hiveCell.Offset)
    if err != nil {
        fmt.Printf("[!] Error retrieving offset of class data\n\tError: %s", err)
        return "", err
    } else if offset >= 0 {
        fmt.Printf("[!] Cell data is not allocated")
        return "", err
    } 

    offset = (offset * -1) - 4

    utf16Bytes := make([]byte, 16)
    bootKeyPart := make([]byte, 8)
    parser.Reader.ReadAt(utf16Bytes, hiveCell.Offset + 4)

    for i, _ := range bootKeyPart {
        bootKeyPart[i] = utf16Bytes[i * 2]
    }

    return string(bootKeyPart), nil

}

func main() {
    regSam := flag.String("sam", "", "Path to SAM hive")
    regSecurity := flag.String("security", "", "Path to SECURITY hive")
    regSystem := flag.String("system", "", "Path to SYSTEM hive")
    // regPath := flag.String("path", "", "Path to check")

    flag.Parse()

    if *regSam == "" {
        flag.Usage()
        return
    }

    if *regSecurity == "" {
        flag.Usage()
        return
    }

    if *regSystem == "" {
        flag.Usage()
        return
    }

    fmt.Println("[+] Parsing registry hives to extract credentials")

    currentTime := time.Now()
    fmt.Printf("[+] Timestamp: %s\n", currentTime.Format(time.UnixDate))

    /*
    ## Retrieving the Boot Key
    */

    fmt.Printf("[+] Extracting boot key from SYSTEM hive\n")

    fileSystem, err := os.OpenFile(*regSystem, os.O_RDONLY, 0600)

    if err != nil {
        fmt.Printf("[!] Error opening SYSTEM hive at '%s'.\n\tError: %s\n", *regSystem, err)
        os.Exit(1)
    }
   
    parserSystem, err := regparser.NewRegistry(fileSystem)

    if err != nil {
        fmt.Printf("[!] Error parsing SYSTEM hive.\n\tError: %s\n", err)
        os.Exit(2)
    }

    var scrambledKey strings.Builder

    for _, key := range []string {"JD", "Skew1", "GBG", "Data"} {
        fmt.Printf("[+] Retrieving part '%s' of the boot key\n", key)

        bootKeyPart, err := RetrieveBootKeyPart(*parserSystem, key)
        if err != nil {
            fmt.Printf("[!] Failed to retrieve it.\n\tError:%s", err)
            os.Exit(3)
        }

        fmt.Printf("[+] Part of the boot key: '%s'\n", string(bootKeyPart))
        scrambledKey.WriteString(string(bootKeyPart))
    }

    fmt.Printf("[+] Scrambled boot key: %s\n", scrambledKey.String())
    
    bootKeyBytes, err := hex.DecodeString(scrambledKey.String())
    if err != nil {
        fmt.Printf("[!] Error decoding the scrambled boot key.\n\tError: %s", err)
        os.Exit(4)
    }

    finalBootKey := make([]byte, 16)
    indexes := []byte {8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

    for i, v := range indexes {
        finalBootKey[i] = bootKeyBytes[v]
    }

    fmt.Printf("[+] Final boot key: %x\n", string(finalBootKey))

    /*
    ## Retrieving user hashes
    */

    fileSam, err := os.OpenFile(*regSam, os.O_RDONLY, 0600)
    parserSam, err := regparser.NewRegistry(fileSam)

    key := parserSam.OpenKey("\\SAM\\Domains\\Account\\Users")
    if key == nil {
        fmt.Printf("[!] Error opening key '%s'\n", key)
        os.Exit(5)
    }



    for _, subkey := range key.Subkeys() {
        if subkey.Name() == "Names" {
            continue
        }

        fmt.Printf("[+] Found user: %s\n", subkey.Name())

        data, err := hex.DecodeString(subkey.Name())
        if err != nil {
            fmt.Printf("[!] Failed to decode hex value '%s'\n", subkey.Name())
            os.Exit(6)
        }

        rid := binary.BigEndian.Uint32(data)
        fmt.Printf("[+] User RID (Relative Identifier): %d\n", rid)

        key := parserSam.OpenKey(fmt.Sprintf("\\SAM\\Domains\\Account\\Users\\%s", subkey.Name()))
        if key == nil {
            fmt.Printf("[!] Error opening key '%s'\n", key)
            os.Exit(5)
        }

        for _, value := range key.Values() {
            if value.ValueName() != "V" {
                continue
            }

            fmt.Printf("[+] Size of Data: 0x%x\n", value.DataSize())
            sectionData := value.ValueData().Data

            // offset calculated based on the size of this structure:
            // https://github.com/fortra/impacket/blob/82267d842c405c2315bff9a9e730c81102c139d2/impacket/examples/secretsdump.py#L183
            data := sectionData[204:]

            userOffset := binary.LittleEndian.Uint32(sectionData[12:16])
            fmt.Printf("[+] Offset of username: 0x%02x\n", userOffset)

            userLength := binary.LittleEndian.Uint32(sectionData[16:20])
            fmt.Printf("[+] Length of username: 0x%02x\n", userLength)

            userName := UTF16LEBytesToUTF8(data[userOffset:userOffset + userLength])
            fmt.Printf("[+] Username: %s\n", userName)
        }
    }
}
