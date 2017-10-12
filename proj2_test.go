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

func TestInit(t *testing.T) {
    t.Log("Initialization test")

    u, err := InitUser("alice","fubar")
    if err != nil {
        // t.Error says the test fails 
        t.Error("Failed to initialize user", err)
    } else {
        // t.Log() only produces output if you run with "go test -v"
        t.Log("Successfully stored user", u)
    }
    // You probably want many more tests here.
}

func TestStorage(t *testing.T) {
    t.Log("User retrieval test")

    v, err := GetUser("alice", "fubar")
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", v)
    }
}

func TestAdversary(t *testing.T) {
    t.Log("Data integrity test")

    // user credentials
    username := "alx"
    password := "hlpme"

    // 
    u, err := InitUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly initialized user", u)
    }

    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly retrieved user", u)
    }

    ds := userlib.DatastoreGetMap()
    sUUID := SecureUUID(username, password)
    ds[sUUID] = nil
    u, err = GetUser(username, password)
    if err == nil {
        t.Error("Failed to reload user:", err)
    } else {
        t.Log("Correctly threw an error, indicating tampering:", err)
    }
}

func TestFilestore(t *testing.T) {
    t.Log("File store/retrieve test")

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
}