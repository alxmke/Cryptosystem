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
func randomBytes(bytes int) (data []byte){
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


/*******************************INSTRUCTOR NOTE*********************************\
  The structure definition for a user record.

  Note: for JSON to marshal/unmarshal, the fields need to be public (start with
  a capital letter)
\*******************************************************************************/
type User struct {
    /*** YOUR CODE HERE ***/
    RSA_key *rsa.PrivateKey
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
    e_salt := randomBytes(16)
    h_salt := randomBytes(16)
    IV := randomBytes(userlib.BlockSize)

    entry_UUID := bytesToUUID(userlib.PBKDF2Key([]byte(password), []byte(username), userlib.AESKeySize))
    E := userlib.CFBEncrypter(userlib.PBKDF2Key([]byte(password), append([]byte(username), e_salt...), userlib.AESKeySize), IV)
    H := userlib.NewHMAC(userlib.PBKDF2Key([]byte(password), append([]byte(username), h_salt...), userlib.AESKeySize*4))
    
    user_rsa_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_rsa_key}

    E_M_userdata,_ := json.Marshal(userdata)
    E.XORKeyStream(E_M_userdata, E_M_userdata)

    nomac_data := append(e_salt, h_salt...)
    nomac_data = append(nomac_data, IV...)
    nomac_data = append(nomac_data, E_M_userdata...) //stupid Go workaround to concat these arrays...

    H.Write(nomac_data)
    hmac_val := H.Sum(nil)

    userlib.DatastoreSet(entry_UUID.String(), append(hmac_val, nomac_data...))
    userlib.KeystoreSet(entry_UUID.String(), user_rsa_key.PublicKey)

    return &userdata, err
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
    entry_UUID := bytesToUUID(userlib.PBKDF2Key([]byte(password), []byte(username), userlib.AESKeySize))
    
    entry_data, valid_user := userlib.DatastoreGet(entry_UUID.String())
    if !valid_user {
        err = errors.New("Error: Invalid credentials")
        return nil, err
    }

    HMAC_val := entry_data[:userlib.HashSize]
    HMAC_in := entry_data[userlib.HashSize:]
    e_salt := entry_data[userlib.HashSize:userlib.HashSize+16]
    h_salt := entry_data[userlib.HashSize+16:userlib.HashSize+32]
    IV := entry_data[userlib.HashSize+32:userlib.HashSize+32+userlib.BlockSize]
    E_M_userdata := entry_data[userlib.HashSize+32+userlib.BlockSize:]

    D := userlib.CFBDecrypter(userlib.PBKDF2Key([]byte(password), append([]byte(username), e_salt...), userlib.AESKeySize), IV)
    H := userlib.NewHMAC(userlib.PBKDF2Key([]byte(password), append([]byte(username), h_salt...), userlib.AESKeySize*4))

    H.Write(HMAC_in)
    if !userlib.Equal(HMAC_val, H.Sum(nil)) {
        err = errors.New("Error: Corrupt data")
        return nil, err
    }

    D.XORKeyStream(E_M_userdata, E_M_userdata)

    var userdata User
    err = json.Unmarshal(E_M_userdata, &userdata)

    return &userdata, err
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
    return
}

/*******************************INSTRUCTOR NOTE*********************************\
  This loads a file from the Datastore.
  
  It should give an error if the file is corrupted in any way.
\*******************************************************************************/
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
    return
}

/*******************************INSTRUCTOR NOTE*********************************\
  You may want to define what you actually want to pass as a sharingRecord to
  serialize/deserialize in the data store.
\*******************************************************************************/
type sharingRecord struct {
    /* SHARING RECORD */
    /*** YOUR CODE HERE ***/
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
    return
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
    return
}

// Removes access for all others.
/*******************************INSTRUCTOR NOTE*********************************\
\*******************************************************************************/
func (userdata *User) RevokeFile(filename string) (err error) {
    /* REVOKE FILE */
    /*** YOUR CODE HERE ***/
    return
}

/***************************************USERLIB FUNCTIONS:****************************************\

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
    COMPLETED []
    • password (assumed to have good entropy)
    • use password to generate one random RSA key
    • use password to help populate the user data structure
    • securely store a copy of the data structure in the data store
    • register a public key in the keystore
    • return the newly populate user data structure
    • the user's name MUST be confidential to the data store 
    InitUser(username string, password string)

    COMPLETED []
    • IF (username and password are correct) THEN (LoadUser() MUST load the appropriate
      information from the data store to populate the User data structure)
    • IF (the data is corrupted) THEN (return an error)
    • the error MAY not distinguish between a bad username, bad password, or corrupted data
    LoadUser(username string, password string)

    COMPLETED []
    • IF (not under attack by {storage server, some user}) THEN (LoadFile() MUST return:
      (last value stored at filename) or (nil if no such file exists) and (MUST NOT raise
      an IntegrityError, or any other error))
    • MUST NOT EVER return an incorrect value (value is incorrect
    LoadFile(filename string)

    COMPLETED []
    • MUST place data at filename (so that future LoadFile()'s return data) {associate file
      with data?}
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename with probability better than random guesses (other
      than len(data))
    StoreFile(filename string, data []byte)

    COMPLETED []
    • MUST append the value data at filename (so that future LoadFile()'s for filename return
      data appended to the previous contents)
    • AppendFile MAY return an error if some parts of the file are corrupted
    • Any person other than the owner of filename MUST NOT be able to learn even partial
      information about data or filename (apart from the length of data and the number of 
      appends conducted to the file) with probability better than random guesses.
    • AppendFile() MUST BE efficient--when adding on to the end of a file, sending the
      unchanged bytes again is unnecessary
    AppendFile(filename string, data []byte)
    
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