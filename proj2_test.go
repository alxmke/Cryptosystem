package proj2

import (
    // test
    "testing"
    // userlib
    "github.com/nweaver/cs161-p2/userlib"
)
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUD(t *testing.T) {
    t.Log("*** User data initialization test ***")

    u, err := InitUser("alice","fubar")
    if err != nil {
        // t.Error says the test fails 
        t.Error("Failed to initialize user (", err, ")")
    } else {
        // t.Log() only produces output if you run with "go test -v"
        t.Log("Successfully stored user", u)
    }
    // You probably want many more tests here.
}

func TestStorageUD(t *testing.T) {
    t.Log("*** User data retrieval test ***")

    v, err := GetUser("alice", "fubar")
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", v)
    }
}

func TestIntegrityUDVA(t *testing.T) {
    t.Log("*** User data integrity vs. adversary test ***")
    // user credentials
    username := "alx"
    password := "hlpme"

    // userdata storage key
    sUUID := SecureUUID(username, password)

    // store initial userdata and confirm it's properly retrievable
    u, err := InitUser(username, password)
    if err != nil {
        t.Error("Failed to reload user (", err, ")")
    } else {
        t.Log("Correctly initialized user", u)
    }

    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", u)
    }

    // tamper with data (crypto format corruption)
    userlib.DatastoreSet(sUUID, randomBytes(16))

    // confirm tampering detection
    u, err = GetUser(username, password)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating crypto format corruption")
    }

    // restore initial userdata and confirm it's properly retrievable
    u, err = InitUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly reinitialized user", u)
    }

    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", u)
    }

    // tamper with data (content corruption)
    userlib.DatastoreSet(sUUID, randomBytes((userlib.HashSize+32+userlib.BlockSize)*2))

    // confirm tampering detection
    u, err = GetUser(username, password)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating content corruption")
    }

    // restore initial userdata and confirm it's properly retrievable
    u, err = InitUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly reinitialized user", u)
    }

    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", u)
    }

    // destroy data
    userlib.DatastoreDelete(sUUID)

    // confirm destruction detected
    u, err = GetUser(username, password)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating data loss")
    }
}

func TestFilestore(t *testing.T) {
    t.Log("*** File store/retrieve test ***")
DebugPrint = true
    // user and file information
    user_RSA_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_RSA_key, "alx", "hlpme"}
    filename := "testfile"
    data := []byte{0,1,2,3,4,5,6,7}

    // store file
    userdata.StoreFile(filename, data)
    t.Log("Filename", filename, "with contents", data, "stored.")
    // load file
    retrieved_data, err := userdata.LoadFile(filename)
    if err != nil {//&& !compare(data, retrieved_data) {
        t.Error("Filesystem failure:", err)
    } else {
        t.Log("Correctly retrieved file with contents", retrieved_data)
    }
DebugPrint = false
}

func TestIntegrityFDVA(t *testing.T) {
    t.Log("*** File data integrity vs. adversary test ***")
}