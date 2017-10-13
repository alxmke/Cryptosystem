package proj2

import (
    // test
    "testing"
    // userlib
    "github.com/nweaver/cs161-p2/userlib"
    // byte function library
    "bytes"
)
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestUserstorage(t *testing.T) {
    t.Log("*** User data storage and retrieval test ***")

    // initialize user
    u, err := InitUser("alice","fubar")
    if err != nil {
        t.Error("Failed to initialize user (", err, ")")
    } else {
        t.Log("Successfully stored user", u)
    }

    // retrieve user    
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
    sUUID := SecureUUID([]byte("alx"), []byte("hlpme"))

    // store initial userdata and confirm it's properly retrievable
    _,_ = InitUser(username, password)
    u, err := GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly initialized and retrieved user", u)
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
    _,_ = InitUser(username, password)
    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly reinitialized and retrieved user", u)
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
    _,_ = InitUser(username, password)
    u, err = GetUser(username, password)
    if err != nil {
        t.Error("Failed to reload user", err)
    } else {
        t.Log("Correctly reinitialized and retrieved user", u)
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

func TestFilestorage(t *testing.T) {
    t.Log("*** File store/retrieve test ***")
    // user and file information
    user_RSA_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_RSA_key, []byte("alx"), []byte("hlpme")}
    filename := "testfile"
    data := randomBytes(8)

    // store file
    userdata.StoreFile(filename, data)
    // load file
    retrieved_data, err := userdata.LoadFile(filename)
    if err != nil {
        t.Error("Filesystem failure:", err)
    } else {
        t.Log("Correctly stored and retrieved file (", filename, ") with contents (", retrieved_data, ")")
    }

    // create new data to append
    new_data := randomBytes(8)
    t.Log("New data to append (", new_data, ")")
    // append new data to file
    userdata.AppendFile(filename, new_data)
    // load updated file
    retrieved_data, err = userdata.LoadFile(filename)
    if err != nil || !bytes.Equal(retrieved_data, append(data, new_data...)) {
        t.Error("Filesystem failure:", err)
    } else {
        t.Log("Correctly stored and retrieved file (", filename, ") with updated contents (", retrieved_data, ")")
    }
}

func TestIntegrityFDVA(t *testing.T) {
    t.Log("*** User data integrity vs. adversary test ***")
    // user and file information
    user_RSA_key,_ := userlib.GenerateRSAKey()
    userdata := User{user_RSA_key, []byte("alx"), []byte("hlpme")}
    filename := "testfile"
    data := randomBytes(4)

    // userdata storage key
    sUUID := SecureUUID([]byte("testfile"), userdata.Password)

    // store initial userdata and confirm it's properly retrievable
    userdata.StoreFile(filename, data)
    retrieved_data, err := userdata.LoadFile(filename)
    if err != nil {
        t.Error("Failed to store and retrieve file", err)
    } else {
        t.Log("Correctly stored and retrieved file (", filename, ") with contents (", retrieved_data, ")")
    }

    // tamper with data (crypto format corruption)
    userlib.DatastoreSet(sUUID, randomBytes(16))

    // confirm tampering detection
    retrieved_data, err = userdata.LoadFile(filename)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating crypto format corruption")
    }

    // restore initial userdata and confirm it's properly retrievable
    userdata.StoreFile(filename, data)
    retrieved_data, err = userdata.LoadFile(filename)
    if err != nil {
        t.Error("Failed to store and retrieve file", err)
    } else {
        t.Log("Correctly stored and retrieved file (", filename, ") with contents (", retrieved_data, ")")
    }

    // tamper with data (content corruption)
    userlib.DatastoreSet(sUUID, randomBytes((userlib.HashSize+32+userlib.BlockSize)*2))

    // confirm tampering detection
    retrieved_data, err = userdata.LoadFile(filename)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating content corruption")
    }

    // restore initial userdata and confirm it's properly retrievable
    userdata.StoreFile(filename, data)
    retrieved_data, err = userdata.LoadFile(filename)
    if err != nil {
        t.Error("Failed to store and retrieve file", err)
    } else {
        t.Log("Correctly stored and retrieved file (", filename, ") with contents (", retrieved_data, ")")
    }

    // destroy data
    userlib.DatastoreDelete(sUUID)

    // confirm destruction detected
    retrieved_data, err = userdata.LoadFile(filename)
    if err == nil {
        t.Error("Failed to throw an error:", err)
    } else {
        t.Log("Correctly threw error (", err, ") indicating data loss")
    }
}