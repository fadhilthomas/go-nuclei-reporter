package main

import "github.com/fadhilthomas/go-nuclei-reporter/model"

func main() {
	database := model.InitSqliteDB()
	if database == nil {
		return
	}
}
