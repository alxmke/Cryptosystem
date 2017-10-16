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

func TestFileshare(t *testing.T) {
    t.Log("*** File share/receive test ***")
    // sender user profile and file creation
    alice,_ := InitUser("alice","alicepw")
    alice_filename := "firstalias"
    file_data := randomBytes(8)
    alice.StoreFile(alice_filename, file_data)

    // receiver user profile and filename creation
    bob,_ := InitUser("bob", "bobpw")
    bob_filename := "secondalias"

    // share file
    msgid, err := alice.ShareFile(alice_filename, string(bob.Username))
    if err != nil {
        t.Error("Failed to send share file credentials for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Succesfully sent share file credentials for file (", alice_filename, ")")
    }

    // receive file
    err = bob.ReceiveFile(bob_filename, string(alice.Username), msgid)
    if err != nil {
        t.Error("Failed to receive shared file credentials for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Succesfully received shared file credentials for file (", alice_filename, ") and stored under receiver filename (", bob_filename, ")")
    }

    // confirm file access for owner and delegee
    retrieved_data, err := alice.LoadFile(alice_filename)
    if err != nil || !bytes.Equal(file_data, retrieved_data) {
        t.Error("Owner file credentials access failure for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Confirmed owner (", string(alice.Username) , ") access/data retention for file (", alice_filename, ")")
    }
    retrieved_data, err = bob.LoadFile(bob_filename)
    if err != nil || !bytes.Equal(file_data, retrieved_data) {
        t.Error("Owner file credentials access failure for file (", bob_filename, ") with error (", err, ")")
    } else {
        t.Log("Delegee owner (", string(bob.Username) , ") access/data retention for file (", bob_filename, ")")
    }
}

func TestIntegrityFSVA(t *testing.T) {
    t.Log("*** File store/retrieve test ***")
    // sender user profile and file creation
    alice,_ := InitUser("alice","alicepw")
    alice_filename := "firstalias"
    file_data := randomBytes(8)
    alice.StoreFile(alice_filename, file_data)

    // receiver user profile and filename creation
    bob,_ := InitUser("bob", "bobpw")
    bob_filename := "secondalias"

    // share file
    msgid, err := alice.ShareFile(alice_filename, string(bob.Username))
    if err != nil {
        t.Error("Failed to send share file credentials for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Succesfully sent share file credentials for file (", alice_filename, ")")
    }

    // MITM transfer attack which modifies contents
    msgid = string(randomBytes(512))

    // receive file
    err = bob.ReceiveFile(bob_filename, string(alice.Username), msgid)
    if err == nil {
        t.Error("Failed to detect file transfer corruption.")
    } else {
        t.Log("Succesfully detected file transfer corruption with error (", err, ")")
    }
}

func TestRevocation(t *testing.T) {
    t.Log("*** File share revocation test ***")
    // sender user profile and file creation
    alice,_ := InitUser("alice","alicepw")
    alice_filename := "firstalias"
    file_data := randomBytes(8)
    alice.StoreFile(alice_filename, file_data)

    // receiver user profile and filename creation
    bob,_ := InitUser("bob", "bobpw")
    bob_filename := "secondalias"

    // second receiver user profile and filename creation
    charlie,_ := InitUser("charlie","charliepw")
    charlie_filename := "thirdalias"

    // share/receive
    msgid, err := alice.ShareFile(alice_filename, string(bob.Username))
    err = bob.ReceiveFile(bob_filename, string(alice.Username), msgid)

    // secondary delegation
    msgid, err = bob.ShareFile(bob_filename, string(charlie.Username))
    err = charlie.ReceiveFile(charlie_filename, string(bob.Username), msgid)

    // revoke file access for all delegees
    err = alice.RevokeFile(alice_filename)
    if err != nil {
        t.Error("Failed to revoke and restore file credentials for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Succesfully revoked shared access for file (", alice_filename, ")")
    }

    // check file access for all users who had access prior to revocation
    retrieved_data, err := charlie.LoadFile(charlie_filename)
    if err == nil {
        t.Error("Erroneous file access retention for previous delegee  (", string(charlie.Username), ")")
    } else {
        t.Log("Confirmed revocation of file access for previous delegee  (", string(charlie.Username), ")")
    }
    retrieved_data, err = bob.LoadFile(bob_filename)
    if err == nil {
        t.Error("Erroneous file access retention for previous delegee  (", string(bob.Username), ")")
    } else {
        t.Log("Confirmed revocation of file access for previous delegee  (", string(bob.Username), ")")
    }
    retrieved_data, err = alice.LoadFile(alice_filename)
    if err != nil || !bytes.Equal(file_data, retrieved_data) {
        t.Error("Owner file credentials access failure for file (", alice_filename, ") with error (", err, ")")
    } else {
        t.Log("Confirmed owner (", string(alice.Username) , ") access/data retention for file (", alice_filename, ")")
    }
}

// given by Nick on Piazza
func Test2(t *testing.T) {
    alice,_ := InitUser("alice","fubar")
    // Having previously created a user "alice" with password "fubar"...
    alice, _ = GetUser("alice", "fubar")
    also_alice, _ := GetUser("alice", "fubar")

    alice.StoreFile("todo", []byte("write tests"))
    todo, _ := also_alice.LoadFile("todo")
    if string(todo) != "write tests" {
        t.Error("Same user and password could not access file: ", todo)
    }
}

func TestIntegrityDataswapU(t *testing.T) {
    t.Log("*** User dataswap corruption detection test ***")
    alice,_ := InitUser("alice","fubar")
    balice,_ := InitUser("balice","fubarb")

    sUUID_a := SecureUUID(alice.Username, alice.Password)
    sUUID_b := SecureUUID(balice.Username, balice.Password)

    adat,_ := userlib.DatastoreGet(sUUID_a)
    bdat,_ := userlib.DatastoreGet(sUUID_b)
    userlib.DatastoreSet(sUUID_a, bdat)
    userlib.DatastoreSet(sUUID_b, adat)

    alice, err := GetUser("alice", "fubar")
    if err == nil {
        t.Error("Failed to throw corruption error.")
    } else {
        t.Log("Properly detected corruption.")
    }

    balice, err = GetUser("balice", "fubarb")
    if err == nil {
        t.Error("Failed to throw corruption error.")
    } else {
        t.Log("Properly detected corruption.")
    }
}