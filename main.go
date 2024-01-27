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
- https://github.com/vphpersson/msdsalgs/blob/ee7525e50ffcff4574371baac226e578078abc03/msdsalgs/crypto.py
- https://docs.python.org/3/library/struct.html
- https://github.com/C-Sto/gosecretsdump/blob/v0.3.1/pkg/samreader/samreader.go
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
    "crypto/rc4"
    "crypto/md5"
    "crypto/des"
    "reflect"
    "errors"
    "bytes"
)

const (
	ErrorGeneric = 1
	ErrorOpenHive = 2
	ErrorOpenKey = 3
	ErrorCreateParser = 4
	ErrorBootKey = 5
	ErrorDecoding = 6
	ErrorHashRevision = 7
	ErrorHashDecryption = 8
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

/*
Function specified here:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1b0094f-2546-431f-b06d-582158a9f2bb

Let I be the little-endian, unsigned integer.

Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
Note that because I is in little-endian byte order, I[0] is the least significant byte.

Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1].
*/
func DeriveKeys(key []byte) (key1 []byte, key2 []byte) {
    key1 = []byte {key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]}
    key2 = []byte {key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]}
    
    return TransformDesKey(key1), TransformDesKey(key2)
}

/*
Adapted from https://github.com/vphpersson/msdsalgs/blob/ee7525e50ffcff4574371baac226e578078abc03/msdsalgs/crypto.py
The process is described here:
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ebdb15df-8d0d-4347-9d62-082e6eccac40

Transform the 7-byte key into an 8-byte key as follows:

Let InputKey be the 7-byte key, represented as a zero-base-index array.
Let OutputKey be an 8-byte key, represented as a zero-base-index array.

Let OutputKey be assigned as follows.

OutputKey[0] = InputKey[0] >> 0x01;
OutputKey[1] = ((InputKey[0]&0x01)<<6) | (InputKey[1]>>2);
OutputKey[2] = ((InputKey[1]&0x03)<<5) | (InputKey[2]>>3);
OutputKey[3] = ((InputKey[2]&0x07)<<4) | (InputKey[3]>>4);
OutputKey[4] = ((InputKey[3]&0x0F)<<3) | (InputKey[4]>>5);
OutputKey[5] = ((InputKey[4]&0x1F)<<2) | (InputKey[5]>>6);
OutputKey[6] = ((InputKey[5]&0x3F)<<1) | (InputKey[6]>>7);
OutputKey[7] = InputKey[6] & 0x7F;

The 7-byte InputKey is expanded to 8 bytes by inserting a 0-bit after every seventh bit.

for( int i=0; i<8; i++ )
{
    OutputKey[i] = (OutputKey[i] << 1) & 0xfe;
}

Let the least-significant bit of each byte of OutputKey be a parity bit.
That is, if the sum of the preceding seven bits is odd, the eighth bit is 0; otherwise, the eighth bit is 1.
The processing starts at the leftmost bit of OutputKey.

*/
func TransformDesKey(inputKey []byte) (outputKey []byte) {
    outputKey = make([]byte, 8)

    outputKey[0] = inputKey[0] >> 0x01
    outputKey[1] = ((inputKey[0] & 0x01) << 6) | (inputKey[1] >> 2)
    outputKey[2] = ((inputKey[1] & 0x03) << 5 | (inputKey[2]) >> 3)
    outputKey[3] = ((inputKey[2] & 0x07) << 4) | (inputKey[3] >> 4)
    outputKey[4] = ((inputKey[3] & 0x0F) << 3) | (inputKey[4] >> 5)
    outputKey[5] = ((inputKey[4] & 0x1F) << 2) | (inputKey[5] >> 6)
    outputKey[6] = ((inputKey[5] & 0x3F) << 1) | (inputKey[6] >> 7)
    outputKey[7] = inputKey[6] & 0x7F

    for i, _ := range outputKey {
        outputKey[i] = (outputKey[i] << 1) & 0xfe
    }

    // TODO: implement parity checks

    return outputKey
}

func RetrieveBootKeyPart(parser regparser.Registry, keyName string) (keyPart string, err error) {
    keyPath := fmt.Sprintf("\\ControlSet001\\Control\\Lsa\\%s", keyName)
    key := parser.OpenKey(keyPath)

    if key == nil {
        return "", errors.New(fmt.Sprintf("[!] Error opening key '%s'", key))
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

/*
Adapted from here:
https://github.com/fortra/impacket/blob/82267d842c405c2315bff9a9e730c81102c139d2/impacket/examples/secretsdump.py#L1290
*/
func CalculateHashedBootKey(parser regparser.Registry, bootKey []byte) (hashedBootKey []byte, err error) {
    keyPath := "\\SAM\\Domains\\Account"
    key := parser.OpenKey(keyPath)
    if key == nil {
        return nil, errors.New(fmt.Sprintf("[!] Error opening key '%s'", key))
    }

    for _, value := range key.Values() {
        if value.ValueName() != "F" {
            continue
        }

        fValueData := value.ValueData().Data

        key0 := int(fValueData[104])
        if key0 != 1 {
            return nil, errors.New(fmt.Sprintf("[!] SAM revision is '%d'", key0))
        }
        // fmt.Printf("[#] SAM Data Revision: %x\n", key0)

        samData := fValueData[104:]
        samKeySalt := samData[8:24]
        // fmt.Printf("[#] SAM Key Salt: %x\n", samKeySalt)

        tmpArray := make([]byte, 120)
        copy(tmpArray[:16], samKeySalt)

        // QWERTY bytes
        qwertyBytes := []byte {33, 64, 35, 36, 37, 94, 38, 42, 40, 41, 113, 119, 101, 114, 116, 121, 85, 73, 79, 80, 65, 122, 120, 99, 118, 98, 110, 109, 81, 81, 81, 81, 81, 81, 81, 81, 81, 81, 81, 81, 41, 40, 42, 64, 38, 37, 0}
        copy(tmpArray[16:63], qwertyBytes)
        copy(tmpArray[63:79], bootKey)

        // digits bytes
        digitsBytes := []byte {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 0}
        copy(tmpArray[79:120], digitsBytes)

        rc4Key := md5.Sum(tmpArray)
        // fmt.Printf("[#] RC4 Key: %x\n", rc4Key)

        rc4Cipher, err := rc4.NewCipher(rc4Key[:])
        if err != nil {
            return nil, err
        }

        var hashedBootKey = make([]byte, 32)
        rc4Cipher.XORKeyStream(hashedBootKey, samData[24:56])

        copy(tmpArray[:16], hashedBootKey[:16])
        copy(tmpArray[16:57], digitsBytes)
        copy(tmpArray[57:73], hashedBootKey[:16])
        copy(tmpArray[73:120], qwertyBytes)


        hashedBootKeyChecksum := md5.Sum(tmpArray)

        if reflect.DeepEqual(hashedBootKeyChecksum[:], hashedBootKey[16:]) {
            return hashedBootKey[:16], nil
        } else {
            return nil, errors.New("Calculated checksum of Hashed Boot Key is not correct")
        }
    }

    return nil, errors.New(fmt.Sprintf("Failed to find value F in '%s'", keyPath))
}

func DecryptHash(userRid []byte, hashedBootKey []byte, junk []byte, isNtHash bool) (decryptedHash []byte, err error) {
    key1, key2 := DeriveKeys(userRid)
    // fmt.Printf("[#] DES keys for decryption:\n\tKey #1: %x\n\tKey #2: %x\n", key1, key2)

    
    var buf bytes.Buffer
    buf.Write(hashedBootKey[:16])
    buf.Write(userRid)

    if isNtHash {
        buf.Write([]byte {78, 84, 80, 65, 83, 83, 87, 79, 82, 68, 0})
    } else {
         buf.Write([]byte {76, 77, 80, 65, 83, 83, 87, 79, 82, 68, 0})
    }

    // fmt.Printf("[#] Data passed to MD5: %x\n", buf.Bytes())

    encryptionKey := md5.Sum(buf.Bytes())
    // fmt.Printf("[#] RC4 Encryption Key: %x\n", encryptionKey)

    rc4Cipher, err := rc4.NewCipher(encryptionKey[:])
    if err != nil {
        // fmt.Printf("[#] Error creating RC4 cipher\n")
        return []byte {}, err
    }

    encryptedDesData := make([]byte, 16)
    rc4Cipher.XORKeyStream(encryptedDesData, junk)

    // fmt.Printf("[#] Encrypted DES data: %x\n", encryptedDesData)

    desCipher1, err := des.NewCipher(key1)
    if err != nil {
        // fmt.Printf("[#] Error creating DES cipher\n")
        return []byte {}, err
    }
    
    desCipher2, err := des.NewCipher(key2)
    if err != nil {
        // fmt.Printf("[#] Error creating DES cipher\n")
        return []byte {}, err
    }

    var buffer bytes.Buffer
    dec := make([]byte, 8)

    desCipher1.Decrypt(dec, encryptedDesData[:8])
    buffer.Write(dec)
    desCipher2.Decrypt(dec, encryptedDesData[8:])
    buffer.Write(dec)
    
    return buffer.Bytes(), nil
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
        os.Exit(ErrorOpenHive)
    }
   
    parserSystem, err := regparser.NewRegistry(fileSystem)

    if err != nil {
        fmt.Printf("[!] Error parsing SYSTEM hive.\n\tError: %s\n", err)
        os.Exit(ErrorCreateParser)
    }

    var scrambledKey strings.Builder

    for _, key := range []string {"JD", "Skew1", "GBG", "Data"} {
        // fmt.Printf("[+] Retrieving part '%s' of the boot key\n", key)

        bootKeyPart, err := RetrieveBootKeyPart(*parserSystem, key)
        if err != nil {
            fmt.Printf("[!] Failed to retrieve it.\n\tError:%s", err)
            os.Exit(ErrorBootKey)
        }

        // fmt.Printf("[+] Part of the boot key: '%s'\n", string(bootKeyPart))
        scrambledKey.WriteString(string(bootKeyPart))
    }

    // fmt.Printf("[+] Scrambled boot key: %s\n", scrambledKey.String())
    
    bootKeyBytes, err := hex.DecodeString(scrambledKey.String())
    if err != nil {
        fmt.Printf("[!] Error decoding the scrambled boot key.\n\tError: %s", err)
        os.Exit(ErrorBootKey)
    }

    finalBootKey := make([]byte, 16)
    indexes := []byte {8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

    for i, v := range indexes {
        finalBootKey[i] = bootKeyBytes[v]
    }

    fmt.Printf("[+] Final boot key: %x\n", string(finalBootKey))

    /*
    ## Calculate Hashed Boot Key
    */
    fileSam, err := os.OpenFile(*regSam, os.O_RDONLY, 0600)
    parserSam, err := regparser.NewRegistry(fileSam)
    hashedBootKey, err := CalculateHashedBootKey(*parserSam, finalBootKey)
    if err != nil {
        fmt.Printf("[!] Failed to calculate hashed boot key.\n\tError: %s\n", err)
        os.Exit(ErrorBootKey)
    }

    fmt.Printf("[+] Hashed boot key: %x\n", hashedBootKey)

    /*
    ## Retrieving user hashes
    */

    key := parserSam.OpenKey("\\SAM\\Domains\\Account\\Users")
    if key == nil {
        fmt.Printf("[!] Error opening key '%s'\n", key)
        os.Exit(ErrorOpenKey)
    }

    for _, subkey := range key.Subkeys() {
        if subkey.Name() == "Names" {
            continue
        }

        // fmt.Printf("[+] Found user: %s\n", subkey.Name())
        fmt.Printf("[+] Found user:\n")

        ridBigEndianBytes, err := hex.DecodeString(subkey.Name())
        if err != nil {
            fmt.Printf("[!] Failed to decode hex value '%s'\n", subkey.Name())
            os.Exit(ErrorDecoding)
        }

        rid := binary.BigEndian.Uint32(ridBigEndianBytes)
        ridLittleEndianBytes := make([]byte, 4)
        binary.LittleEndian.PutUint32(ridLittleEndianBytes, rid)

        
        fmt.Printf("\tRID: %d\n", rid)

        key := parserSam.OpenKey(fmt.Sprintf("\\SAM\\Domains\\Account\\Users\\%s", subkey.Name()))
        if key == nil {
            fmt.Printf("[!] Error opening key '%s'\n", key)
            os.Exit(ErrorOpenKey)
        }

        for _, value := range key.Values() {
            if value.ValueName() != "V" {
                continue
            }

            // fmt.Printf("[+] Size of Data: 0x%x\n", value.DataSize())
            sectionData := value.ValueData().Data

            // offset calculated based on the size of this structure:
            // https://github.com/fortra/impacket/blob/82267d842c405c2315bff9a9e730c81102c139d2/impacket/examples/secretsdump.py#L183
            data := sectionData[204:]

            userOffset := binary.LittleEndian.Uint32(sectionData[12:16])
            // fmt.Printf("[+] Offset of username: 0x%02x\n", userOffset)

            userLength := binary.LittleEndian.Uint32(sectionData[16:20])
            // fmt.Printf("[+] Length of username: 0x%02x\n", userLength)

            userName := UTF16LEBytesToUTF8(data[userOffset:userOffset + userLength])
            fmt.Printf("\tUsername: %s\n", userName)

            /*
            ### Calculate NT and LM hashes (old style for now)
            */

            userLmHashLength := binary.LittleEndian.Uint32(sectionData[160:164])
            // fmt.Printf("[+] Length of LM hash: %d\n", userLmHashLength)

            userLmHashOffset := binary.LittleEndian.Uint32(sectionData[156:160])
            // fmt.Printf("[+] Offset of LM hash: 0x%02x\n", userLmHashOffset)

            /*
            ### Check the revision of the LM and NT hashes: if they are not
            equal to 1, then it means it's a recent version of Windows
            using AES encryption
            */

            hashRevisionBytes := data[userLmHashOffset+2:userLmHashOffset+4]
            userLmHashRevision := binary.LittleEndian.Uint16(hashRevisionBytes)

            // fmt.Printf("[+] Revision of the LM Hash: %d\n", userLmHashRevision)
            if userLmHashRevision != 1 {
                fmt.Printf("[!] Current revision of LM hash (%d) is not supported\n", userLmHashRevision)
                os.Exit(ErrorHashRevision)
            }

            var userLmHash []byte
            if userLmHashLength >= 20 {
                // We're skipping the first 4 bytes of the hash data, because they contain
                // PekID (still don't know what this is) and the hash revision
                userLmHash = data[userLmHashOffset + 4:userLmHashOffset + userLmHashLength]
                // fmt.Printf("[+] Encrypted LM hash: %02x\n", userLmHash)

                decryptedLmHash, err := DecryptHash(ridLittleEndianBytes, hashedBootKey, userLmHash, false)
                if err != nil {
                    fmt.Printf("[!] Error decrypting hash.\n\tError: %s\n", err)
                    os.Exit(ErrorHashDecryption)
                }

                fmt.Printf("\tLM Hash: %x\n", decryptedLmHash)

            }

            userNtHashLength := binary.LittleEndian.Uint32(sectionData[172:176])
            // fmt.Printf("[+] Length of NT hash: %d\n", userNtHashLength)

            userNtHashOffset := binary.LittleEndian.Uint32(sectionData[168:172])
            // fmt.Printf("[+] Offset of NT Hash: 0x%02x\n", userNtHashOffset)

            var userNtHash []byte
            if userNtHashLength >= 20 {
                userNtHash = data[userNtHashOffset + 4:userNtHashOffset + userNtHashLength]
                // fmt.Printf("[+] Encrypted NT hash: %02x\n", userNtHash)
                
                decryptedNtHash, err := DecryptHash(ridLittleEndianBytes, hashedBootKey, userNtHash, true)
                if err != nil {
                    fmt.Printf("[!] Error decrypting hash.\n\tError: %s\n", err)
                    os.Exit(ErrorHashDecryption)
                }

                fmt.Printf("\tNT Hash: %x\n", decryptedNtHash)
            }
        }
    }
}
