package proj2

/*******************************INSTRUCTOR NOTE*********************************\
  You MUST NOT change what you import. If you add ANY additional imports it
  will break the autograder, and we will be Very Upset.
\*******************************************************************************/
import (

    // You neet to add with
    // go get github.com/nweaver/cs161-p2/userlib
    "github.com/nweaver/cs161-p2/userlib"

    // Life is much easier with json:  You are
    // going to want to use this so you can easily
    // turn complex structures into strings etc...
    "encoding/json"

    // Likewise useful for debugging etc
    "encoding/hex"
    
    // UUIDs are generated right based on the crypto RNG
    // so lets make life easier and use those too...
    //
    // You need to add with "go get github.com/google/uuid"
    "github.com/google/uuid"

    // For the useful little debug printing function
    "fmt"
    "time"
    "os"
    "strings"

    // I/O
    "io"
    
    // Want to import errors
    "errors"
    
    // These are imported for the structure definitions.  You MUST
    // not actually call the functions however!!!
    // You should ONLY call the cryptographic functions in the
    // userlib, as for testing we may add monitoring functions.
    // IF you call functions in here directly, YOU WILL LOSE POINTS
    // EVEN IF YOUR CODE IS CORRECT!!!!!
    "crypto/rsa"
)


/*******************************INSTRUCTOR NOTE*********************************\
  This serves two purposes: It shows you some useful primitives and it
  suppresses warnings for items not being imported
\*******************************************************************************/
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

/*******************************INSTRUCTOR NOTE*********************************\
  Helper function: Takes the first 16 bytes and converts it into the UUID type,
  UUID is len()=16 []byte
\*******************************************************************************/
func bytesToUUID(data []byte) (ret uuid.UUID) {
    for x := range(ret){
        ret[x] = data[x]
    }
    return
}

/*******************************INSTRUCTOR NOTE*********************************\
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

/*******************************INSTRUCTOR NOTE*********************************\
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

/*******************************INSTRUCTOR NOTE*********************************\
  The structure definition for a user record.

  Note: for JSON to marshal/unmarshal, the fields need to be public (start with
  a capital letter)
\*******************************************************************************/
type User struct {
    /*** YOUR CODE HERE ***/
    RSA_key *rsa.PrivateKey
    Username []byte
    Password []byte
}

/*******************************INSTRUCTOR NOTE*********************************\
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
\*******************************************************************************/
/*
    • password (assumed to have good entropy)
    • use password to generate one random RSA key
    • use password to help populate the user data structure
    • securely store a copy of the data structure in the data store
    • register a public key in the keystore
    • return the newly populated user data structure
    • the user's name MUST be confidential to the data store 
    InitUser(username string, password string)
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
    /* INIT USER */
    /*** YOUR CODE HERE ***/
    b_username := []byte(username)
    b_password := []byte(password)

    user_rsa_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_rsa_key, b_username, b_password} // consider changing b_password => randomBytes(64)?
    m_userdata,_ := json.Marshal(userdata)
    SecureStore(m_userdata, b_password, b_username)

    userlib.KeystoreSet(username, user_rsa_key.PublicKey)

    return &userdata, nil
}

/*******************************INSTRUCTOR NOTE*********************************\
  This fetches the user information from the Datastore.  It should fail with an
  error if the user/password is invalid, or if the user data was corrupted, or
  if the user can't be found.
\*******************************************************************************/
/*
    • IF (username and password are correct) THEN (LoadUser() MUST load the appropriate
      information from the data store to populate the User data structure)
    • IF (the data is corrupted) THEN (return an error)
    • the error MAY not distinguish between a bad username, bad password, or corrupted data
    LoadUser(username string, password string)
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
    /* LOAD USER */
    /*** YOUR CODE HERE ***/
    m_data, err := SecureGet([]byte(password), []byte(username))
    if err != nil {
        return nil, err
    }

    var userdata User
    json.Unmarshal(m_data, &userdata)

    return &userdata, nil
}

/*******************************INSTRUCTOR NOTE*********************************\
  This stores a file in the datastore.

  The name of the file should NOT be revealed to the datastore!
\*******************************************************************************/
/*
    • MUST place data at filename (so that future LoadFile()'s return data) {associate file
      with data?}
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename with probability better than random guesses (other
      than len(data))--filename MUST NOT be revealed to the datastore
    StoreFile(filename string, data []byte)
*/
func (userdata *User) StoreFile(filename string, data []byte) {
    /* STORE FILE */
    /*** YOUR CODE HERE ***/
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

/*******************************INSTRUCTOR NOTE*********************************\
  This adds on to an existing file.

  Append should be efficient, you shouldn't rewrite or reencrypt the existing
  file, but only whatever additional information and metadata you need.
\*******************************************************************************/
/*
    • MUST append the value data at filename (so that future LoadFile()'s for filename return
      data appended to the previous contents)
    • AppendFile MAY return an error if some parts of the file are corrupted
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename (apart from the length of data and the number of 
      appends conducted to the file) with probability better than random guesses.
    • AppendFile() MUST BE efficient--when adding on to the end of a file, sending the
      unchanged bytes again is unnecessary
    AppendFile(filename string, data []byte)
*/
func (userdata *User) AppendFile(filename string, data []byte) (err error){
    /* APPEND FILE */
    /*** YOUR CODE HERE ***/
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

/*******************************INSTRUCTOR NOTE*********************************\
  This loads a file from the Datastore.
  
  It should give an error if the file is corrupted in any way.
\*********************************************************s**********************/
/*
    • IF (not under attack by {storage server, some user}) THEN (LoadFile() MUST return:
      (last value stored at filename) or (nil if no such file exists) and (MUST NOT raise
      an IntegrityError, or any other error))
    • MUST NOT EVER return an incorrect value (value is incorrect
    LoadFile(filename string)
*/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
    /* LOAD FILE */
    /*** YOUR CODE HERE ***/
    // retrieve file credentials
    m_file_credentials, err := SecureGet(userdata.Password, []byte(filename))
    if err != nil {
        return nil, err 
    }
    var file_credentials FileCredentials
    json.Unmarshal(m_file_credentials, &file_credentials)

    // retrieve file
    m_file, err := SecureGet(file_credentials.File_key, file_credentials.File_salt)
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
    /*** YOUR CODE HERE ***/
    File_key []byte
    File_salt []byte
}

type File struct {
    /*** YOUR CODE HERE ***/
    N_appends int
    Filedata_keys [][]byte
    Filedata_salts [][]byte
}

/*******************************INSTRUCTOR NOTE*********************************\
  You may want to define what you actually want to pass as a sharingRecord to
  serialize/deserialize in the data store.
\*******************************************************************************/
type sharingRecord struct {
    /*** YOUR CODE HERE ***/
    // unused
}

/*******************************INSTRUCTOR NOTE*********************************\
  ShareFile() creates a sharing record, which is a key pointing to something in
  the datastore to share with the recipient.

  This enables the recipient to access the encrypted file as well for
  reading/appending.

  NOTE: neither the recipient NOR the datastore should gain any information
  about what the sender calls the file.  Only the recipient can access the
  sharing record, and only the recipient should be able to know the sender.
\*******************************************************************************/
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
    /* SHARE FILE */
    /*** YOUR CODE HERE ***/
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

/*******************************INSTRUCTOR NOTE*********************************\
  NOTE: recipient's filename can be different from the sender's filename. The
  recipient should not be able to discover the sender's view on what the
  filename even is!  However, the recipient must ensure that it is authentically
  from the sender.
\*******************************************************************************/
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
    /* RECEIVE FILE */
    /*** YOUR CODE HERE ***/
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

/*******************************INSTRUCTOR NOTE*********************************\
  Removes access to the given file for all non-owner users.
\*******************************************************************************/
func (userdata *User) RevokeFile(filename string) (err error) {
    /* REVOKE FILE */
    /*** YOUR CODE HERE ***/
    /* (revocation if we don't care if the old file copy remains accessible on data store)
        data, err := userdata.LoadFile(filename)
        if err != nil {
            return err
        }
        userdata.StoreFile(filename, data)
        return nil
    */

    // retrieve current file location
    m_file_credentials, err := SecureGet(userdata.Password, []byte(filename))
    if err != nil {
        return err 
    }
    var file_credentials FileCredentials
    json.Unmarshal(m_file_credentials, &file_credentials)

    // retrieve file, delete it from the datastore, and properly reformat it
    m_file, err := SecureGet(file_credentials.File_key, file_credentials.File_salt)
    if err != nil {
        return err
    }
    userlib.DatastoreDelete(SecureUUID(file_credentials.File_salt, file_credentials.File_key))
    var file File
    json.Unmarshal(m_file, &file)

    // piecing together the complete file data
    var complete_data []byte
    var current_data []byte
    // note: i ranges [0, N_appends], by implementation
    for i:=0; i<=file.N_appends; i++ {
        // retrieve data chunk from datastore and delete it from the datastore
        current_m_data, err := SecureGet(file.Filedata_keys[i], file.Filedata_salts[i])
        if err != nil {
            return err
        }
        userlib.DatastoreDelete(SecureUUID(file.Filedata_salts[i], file.Filedata_keys[i]))
        // properly reformat data chunk and place it into its position
        json.Unmarshal(current_m_data, &current_data) 
        complete_data = append(complete_data, current_data...)
    }

    // store file with most recent data at fresh, secret, unshared location
    userdata.StoreFile(filename, complete_data)
    return nil
}

/***************************************USERLIB FUNCTIONS:****************************************\userlib.

    • Set and Get from the Datastore
        DatastoreSet(key string, value []byte)
        DatastoreGet(key string)                                    (value []byte, ok bool)
        DatastoreDelete(key string)
        DatastoreClear()
        DatastoreGetMap()                                           (map[string] []byte)

    • Set and Get from the Keystore
        KeystoreSet(key string, value rsa.PublicKey)
        KeystoreGet(key string)                                     (value rsa.PublicKey, ok bool)
        KeystoreClear()
        KeystoreGetMap()                                            (map[string] rsa.PublicKey) 

    • RSA Key Generation
        GenerateRSAKey()                                            (*rsa.PrivateKey, error)

    • RSA Encrypt and Decrypt
        RSAEncrypt(pub *rsa.PublicKey, msg []byte, tag []byte)      ([] byte, error)
        RSADecrypt(priv *rsa.PrivateKey, msg []byte, tag []byte)    ([] byte, error)

    • RSA Sign and Verify
        RSASign(priv *rsa.PrivateKey, msg []byte)                   ([]byte, error)
        RSAVerify(pub *rsa.PublicKey, msg []byte, sig []byte)       (error)

    • HMAC and SHA256 MAC Creation and Equality Testing
        NewHMAC(key [] byte)                                        (hash.Hash)
        Equal(a []byte , b []byte)                                  (bool)
        NewSHA256()                                                 (hash.Hash)

    • PBKDF2 Key Derivation
        PBKDF2Key(password []byte, salt []byte, keyLen int)         ([]byte)

    • CFB Encryption and Decryption
        CFBEncrypter(key []byte, iv []byte)                         (cipher.Stream)
        CFBDecrypter(key []byte, iv []byte)                         (cipher.Stream)

\*************************************************************************************************/

/*******************************************PART 1:***********************************************\
    COMPLETED [x]
    • password (assumed to have good entropy)
    • use password to generate one random RSA key
    • use password to help populate the user data structure
    • securely store a copy of the data structure in the data store
    • register a public key in the keystore
    • return the newly populate user data structure
    • the user's name MUST be confidential to the data store 
    InitUser(username string, password string)

    COMPLETED [x]
    • IF (username and password are correct) THEN (LoadUser() MUST load the appropriate
      information from the data store to populate the User data structure)
    • IF (the data is corrupted) THEN (return an error)
    • the error MAY not distinguish between a bad username, bad password, or corrupted data
    LoadUser(username string, password string)

    COMPLETED [x]
    • MUST place data at filename (so that future LoadFile()'s return data) {associate file
      with data?}
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename with probability better than random guesses (other
      than len(data))
    StoreFile(filename string, data []byte)

    COMPLETED [x]
    • MUST append the value data at filename (so that future LoadFile()s for filename return
      data appended to the previous contents)
    • AppendFile MAY return an error if some parts of the file are corrupted
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename (apart from the length of data and the number of 
      appends conducted to the file) with probability better than random guesses.
    • AppendFile() MUST BE efficient--when adding on to the end of a file, sending the
      unchanged bytes again is unnecessary
    AppendFile(filename string, data []byte)

    COMPLETED [x]
    • IF (not under attack by {storage server, some user}) THEN (LoadFile() MUST return:
      (last value stored at filename) or (nil if no such file exists) and (MUST NOT raise
      an IntegrityError, or any other error))
    • MUST NOT EVER return an incorrect value (value is incorrect
    LoadFile(filename string)
    
    • filenames are alphanumeric
    • filenames are not empy
    • file contents (data) can be arbitrary
    • usernames are [a-z]+
    • AppendFile() MUST BE efficient--when adding on to the end of a file, sending the
      unchanged bytes again is unnecessary
    • do not change the storage server
    • protect the confidentiality and integrity of {file contents, filename, file owner name}
    • file length and filename length don't need to be kept confidential
    • different (non-adversarial) users //SHOULD BE// allowed to have files with the same name
      as other users (and not overwrite each other's files)
    • an adversary who has access to the datastore's list of keys may be able to overwrite a
      user's valid data, but any changes //SHOULD BE// reported as an error.
    • an adversary who does not have access to the datastore's list of keys must not be able
      to overwrite or delete files.
    • the client is secure if it satisfies the following scenario: {see pg. 6-7 proj-2 spec}

\*************************************************************************************************/

/*******************************************PART 2:***********************************************\

    - 
    FN(,)
    
    - 
    FN(,)

    - 
    FN(,)

\*************************************************************************************************/