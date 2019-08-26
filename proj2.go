package proj2

import (

    "github.com/nweaver/cs161-p2/userlib"
    "encoding/json"
    "encoding/hex"
    "github.com/google/uuid"
    "fmt"
    "time"
    "os"
    "strings"
    "io"
    "errors"
    "crypto/rsa"
)

func someUsefulThings(){
    // Creates a random UUID
    f := uuid.New()
    debugMsg("UUID as string:%v", f.String())
    
    // Example of writing over a byte of f
    f[0] = 10
    debugMsg("UUID as string:%v", f.String())

    // takes a sequence of bytes and renders as hex
    h := hex.EncodeToString([]byte("fubar"))
    debugMsg("The hex: %v", h)
    
    // Marshals data into a JSON representation
    // Will actually work with go structures as well
    d,_ := json.Marshal(f)
    debugMsg("The json data: %v", string(d))
    var g uuid.UUID
    json.Unmarshal(d, &g)
    debugMsg("Unmashaled data %v", g.String())

    // This creates an error type
    debugMsg("Creation of error %v", errors.New("This is an error"))

    // And a random RSA key.  In this case, ignoring the error
    // return value
    var key *rsa.PrivateKey
    key,_ = userlib.GenerateRSAKey()
    debugMsg("Key is %v", key)
}

/*******************************      NOTE     *********************************\
  Helper function: Takes the first 16 bytes and converts it into the UUID type,
  UUID is len()=16 []byte
\*******************************************************************************/
func bytesToUUID(data []byte) (ret uuid.UUID) {
    for x := range(ret){
        ret[x] = data[x]
    }
    return
}

/*******************************      NOTE     *********************************\
  Helper function: Returns a byte slice of the specificed size filled with
  random data
\*******************************************************************************/
func randomBytes(bytes int) (data []byte) {
    data = make([]byte, bytes)
    if _, err := io.ReadFull(userlib.Reader, data); err != nil {
        panic(err)
    }
    return data

}
var DebugPrint = false

/*******************************      NOTE     *********************************\
  Helper function: Does formatted printing to stderr if the DebugPrint global
  is set.  All our testing ignores stderr, so feel free to use this for any
  sort of testing you want
\*******************************************************************************/
func debugMsg(format string, args ...interface{}) {
    if DebugPrint{
        msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
        fmt.Fprintf(os.Stderr,
            msg + strings.Trim(format, "\r\n ") + "\n", args...)
    }
}

func SecureUUID(name []byte, key []byte) (string) {
    /*** YOUR CODE HERE ***/
    return bytesToUUID(userlib.PBKDF2Key(key, name, userlib.AESKeySize)).String()
}

func SecureStore(m_data []byte, key []byte, name []byte) {
    /*** YOUR CODE HERE ***/
    e_salt := randomBytes(16)
    h_salt := randomBytes(16)
    IV := randomBytes(userlib.BlockSize)

    E := userlib.CFBEncrypter(userlib.PBKDF2Key(key, append(name, e_salt...), userlib.AESKeySize), IV)
    H := userlib.NewHMAC(userlib.PBKDF2Key(key, append(name, h_salt...), userlib.AESKeySize*4))

    E.XORKeyStream(m_data, m_data)

    nomac_data := append(e_salt, h_salt...)
    nomac_data = append(nomac_data, IV...)
    nomac_data = append(nomac_data, m_data...) //stupid Go workaround to concat these arrays...

    H.Write(nomac_data)
    hmac_val := H.Sum(nil)

    userlib.DatastoreSet(SecureUUID(name, key), append(hmac_val, nomac_data...))
}

func SecureGet(key []byte, name []byte) (m_data []byte, err error) {
    /*** YOUR CODE HERE ***/
    entry_data, valid := userlib.DatastoreGet(SecureUUID(name, key))
    if !valid {
        return nil, errors.New("Error: Invalid credentials")
    }

    if len(entry_data) < userlib.HashSize+32+userlib.BlockSize {
        return nil, errors.New("Error: Corrupt data")
    }

    hmac_val := entry_data[:userlib.HashSize]
    hmac_in := entry_data[userlib.HashSize:]
    e_salt := entry_data[userlib.HashSize:userlib.HashSize+16]
    h_salt := entry_data[userlib.HashSize+16:userlib.HashSize+32]
    IV := entry_data[userlib.HashSize+32:userlib.HashSize+32+userlib.BlockSize]
    em_data := entry_data[userlib.HashSize+32+userlib.BlockSize:]

    D := userlib.CFBDecrypter(userlib.PBKDF2Key(key, append(name, e_salt...), userlib.AESKeySize), IV)
    H := userlib.NewHMAC(userlib.PBKDF2Key(key, append(name, h_salt...), userlib.AESKeySize*4))

    H.Write(hmac_in)
    if !userlib.Equal(hmac_val, H.Sum(nil)) {
        return nil, errors.New("Error: Corrupt data")
    }

    D.XORKeyStream(em_data, em_data)
    m_data = em_data
    return m_data, nil
}

/*******************************      NOTE     *********************************\
  The structure definition for a user record.

  Note: for JSON to marshal/unmarshal, the fields need to be public (start with
  a capital letter)
\*******************************************************************************/
type User struct {
    RSA_key *rsa.PrivateKey
    Username []byte
    Password []byte
}

/*******************************      NOTE     *********************************\
  This creates a user.  It will only be called once for a user (unless the
  keystore and datastore are cleared during testing purposes)

  It should store a copy of the userdata, suitably encrypted, in the datastore
  and should store the user's public key in the keystore.

  The datastore may corrupt or completely erase the stored information, but
  nobody outside should be able to get at the stored User data: the name used in
  the datastore should not be guessable without also knowing the password and
  username.

  You are not allowed to use any global storage other than the keystore and the
  datastore functions in the userlib library.

  You can assume the user has a STRONG password
    • password (assumed to have good entropy)
    • use password to generate one random RSA key
    • use password to help populate the user data structure
    • securely store a copy of the data structure in the data store
    • register a public key in the keystore
    • return the newly populated user data structure
    • the user's name MUST be confidential to the data store 
\*******************************************************************************/
func InitUser(username string, password string) (userdataptr *User, err error) {
    b_username := []byte(username)
    b_password := []byte(password)

    user_rsa_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_rsa_key, b_username, b_password}
    m_userdata,_ := json.Marshal(userdata)
    SecureStore(m_userdata, b_password, b_username)

    userlib.KeystoreSet(username, user_rsa_key.PublicKey)

    return &userdata, nil
}

/*******************************      NOTE     *********************************\
  This fetches the user information from the Datastore.  It will fail with an
  error if the user/password is invalid, or if the user data was corrupted, or
  if the user can't be found.
    • IF (username and password are correct) THEN (LoadUser() MUST load the 
      appropriate information from the data store to populate the User data
      structure)
    • IF (the data is corrupted) THEN (return an error)
    • the error MAY not distinguish between a bad username, bad password, or
      corrupted data
\*******************************************************************************/
func GetUser(username string, password string) (userdataptr *User, err error) {
    m_data, err := SecureGet([]byte(password), []byte(username))
    if err != nil {
        return nil, err
    }

    var userdata User
    json.Unmarshal(m_data, &userdata)

    return &userdata, nil
}

/*******************************      NOTE     *********************************\
  This stores a file in the datastore.
    • MUST place data at filename (so that future LoadFile()'s return data)
    • Any person other than the owner of filename WILL NOT be able to learn even partial
      information about data or filename with probability better than random guesses (other
      than len(data))--filename WILL NOT be revealed to the datastore
\*******************************************************************************/
func (userdata *User) StoreFile(filename string, data []byte) {
    // creating file credentials
    file_credentials := FileCredentials{randomBytes(64), randomBytes(16)}
    // creating the initial file
    file := File{0, [][]byte{randomBytes(64)}, [][]byte{randomBytes(16)}}
    // storing the file credentials
    m_file_credentials,_ := json.Marshal(file_credentials)
    SecureStore(m_file_credentials, userdata.Password, []byte(filename))
    // storing the file
    m_file,_ := json.Marshal(file)
    SecureStore(m_file, file_credentials.File_key, file_credentials.File_salt)
    // storing the file data
    m_data,_ := json.Marshal(data)
    SecureStore(m_data, file.Filedata_keys[0], file.Filedata_salts[0])
}

/*******************************      NOTE     *********************************\
  This adds on to an existing file.
    • MUST append the value data at filename (so that future LoadFile()'s for filename return
      data appended to the previous contents)
    • AppendFile MAY return an error if some parts of the file are corrupted
    • Any person other than the owner of filename WILL NOT be able to learn even partial
      information about data or filename (apart from the length of data and the number of 
      appends conducted to the file) with probability better than random guesses.
\*******************************************************************************/
func (userdata *User) AppendFile(filename string, data []byte) (err error){
    // retrieve file credentials
    m_file_credentials, err := SecureGet(userdata.Password, []byte(filename))
    if err != nil {
        return err 
    }
    var file_credentials FileCredentials
    json.Unmarshal(m_file_credentials, &file_credentials)

    // retrieve file
    m_file, err := SecureGet(file_credentials.File_key, file_credentials.File_salt)
    if err != nil {
        return err
    }
    var file File
    json.Unmarshal(m_file, &file)

    // append data to file
    file.N_appends++
    file.Filedata_keys = append(file.Filedata_keys, randomBytes(64))
    file.Filedata_salts = append(file.Filedata_salts, randomBytes(16))

    // store data
    m_data,_ := json.Marshal(data)
    SecureStore(m_data, file.Filedata_keys[file.N_appends], file.Filedata_salts[file.N_appends])

    // update/store new file version
    m_file,_ = json.Marshal(file)
    SecureStore(m_file, file_credentials.File_key, file_credentials.File_salt)

    return nil
}

/*******************************      NOTE     *********************************\
  This loads a file from the Datastore.
  
  gives an error if the file is corrupted in any way.
  
  return:
      last value stored at filename or (nil if no such file exists)
\*******************************************************************************/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
    // retrieve file credentials
    m_file_credentials, err := SecureGet(userdata.Password, []byte(filename))
     if err != nil && err.Error() == "Error: Invalid credentials" {
        return nil, nil // specs strangely specify non-existance of file as non-error
    }
    if err != nil {
        return nil, err 
    }
    var file_credentials FileCredentials
    json.Unmarshal(m_file_credentials, &file_credentials)

    // retrieve file
    m_file, err := SecureGet(file_credentials.File_key, file_credentials.File_salt)
    if err != nil && err.Error() == "Error: Invalid credentials" {
        return nil, nil // specs strangely specify non-existance of file as non-error
    }
    if err != nil {
        return nil, err
    }
    var file File
    json.Unmarshal(m_file, &file)

    // piecing together the file data
    var complete_data []byte
    var current_data []byte
    // note: i ranges [0, N_appends], by implementation
    for i:=0; i<=file.N_appends; i++ {
        current_m_data, err := SecureGet(file.Filedata_keys[i], file.Filedata_salts[i])
        if err != nil {
            return nil, err
        }
        json.Unmarshal(current_m_data, &current_data)
        complete_data = append(complete_data, current_data...)
    }

    return complete_data, nil
}

type FileCredentials struct {
    File_key []byte
    File_salt []byte
}

type File struct {
    N_appends int
    Filedata_keys [][]byte
    Filedata_salts [][]byte
}

/*******************************      NOTE     *********************************\
  ShareFile() creates a sharing record, which is a key pointing to something in
  the datastore to share with the recipient.

  This enables the recipient to access the encrypted file as well for
  reading/appending.

  NOTE: neither the recipient NOR the datastore should gain any information
  about what the sender calls the file.  Only the recipient can access the
  sharing record, and only the recipient should be able to know the sender.
\*******************************************************************************/
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
    // retrieving file credentials
    m_file_credentials, err := SecureGet(userdata.Password, []byte(filename))
    if err != nil {
        return "", err 
    }
    var file_credentials FileCredentials
    json.Unmarshal(m_file_credentials, &file_credentials)

    // retrieve recipient's public key
    recipient_pubkey, valid_recipient := userlib.KeystoreGet(recipient)
    if !valid_recipient {
        return "", errors.New("Error: Recipient key does not exist")
    }

    // rsa encrypt using recipient's public key
    e_msg, err := userlib.RSAEncrypt(&recipient_pubkey, append(file_credentials.File_key, file_credentials.File_salt...), []byte("file share"))
    if err != nil {
        return "", err
    }

    // rsa sign using sender's private key
    e_msg_sig, err := userlib.RSASign(userdata.RSA_key, e_msg)
    if err != nil {
        return "", err
    }

    // return encrypted and signed message (cast to string)
    return string(append(e_msg_sig, e_msg...)), nil
}

/*******************************      NOTE     *********************************\
  recipient's filename can be different from the sender's filename. The
  recipient should not be able to discover the sender's view on what the
  filename even is!  However, the recipient must ensure that it is authentically
  from the sender.
\*******************************************************************************/
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
    // recasting, reformatting, and splitting msgid to components
    b_msgid := []byte(msgid)
    e_msg_sig := b_msgid[:256]      // index 256, from len() of return of PKCS#1 Sig
    e_msg := b_msgid[256:]
    // fetch the sender's public key
    sender_pubkey, valid_sender := userlib.KeystoreGet(sender)
    if !valid_sender {
        return errors.New("Error: Sender key does not exist")
    }

    // verify sender's signature
    err = userlib.RSAVerify(&sender_pubkey, e_msg, e_msg_sig)
    if err != nil {
        return err //errors.New("RSA verification failure")
    }

    // decrypt message holding shared file credentials 
    key_salt, err := userlib.RSADecrypt(userdata.RSA_key, e_msg, []byte("file share"))
    if err != nil {
        return err
    }

    // creating file credentials that give access to shared file
    file_credentials := FileCredentials{key_salt[:64], key_salt[64:]}

    // storing the file credentials with filename
    m_file_credentials,_ := json.Marshal(file_credentials)
    SecureStore(m_file_credentials, userdata.Password, []byte(filename))

    return nil
}

/*******************************      NOTE     *********************************\
  Removes access to the given file for all non-owner users.
\*******************************************************************************/
func (userdata *User) RevokeFile(filename string) (err error) {
    data, err := userdata.LoadFile(filename)
    if err != nil {
        return err
    }
    userdata.StoreFile(filename, data)
    return nil
