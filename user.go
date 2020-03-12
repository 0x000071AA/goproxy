package main

import (
	"encoding/json"
	"net/http"
)

var sqlClient = SqlConnect("")

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	err := sqlClient.Query("", "")
	if err != nil {
		e := HttpInternalServerError(err.Error())
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	if true {
		e := HttpNotFound("User not found")
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}
	res := HttpGet("")
	w.WriteHeader(res.status)
	json.NewEncoder(w).Encode(res)
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	var u User
	if r.Body == nil {
		e := HttpBadRequest("No body provided")
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		e := HttpBadRequest("Invalid json")
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	user, errInsert := sqlClient.Insert("")
	if errInsert != nil {
		e := HttpInternalServerError(errInsert.Error())
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}
	res := HttpCreated("user created")
	w.WriteHeader(res.status)
	json.NewEncoder(w).Encode(res)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {

	err := sqlClient.Delete("")
	if err != nil {
		e := HttpInternalServerError(err.Error())
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	res := HttpDeleted("user deleted")
	w.WriteHeader(res.status)
	json.NewEncoder(w).Encode(res)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	var u User
	if r.Body == nil {
		e := HttpBadRequest("No body provided")
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		e := HttpBadRequest("Invalid json")
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}

	_, errUpdate := sqlClient.Update("")
	if errUpdate != nil {
		e := HttpInternalServerError(errUpdate.Error())
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(e)
		return
	}
	res := HttpUpdated("user updated")
	w.WriteHeader(res.status)
	json.NewEncoder(w).Encode(res)
}
