package main

import (
	"database/sql"
	"log"

	_ "github.com/siddontang/go-mysql/driver"
)

type MySQLClient struct {
	dsn      string
	database *sql.DB
}

var clients map[string]*MySQLClient

// "user:password@tcp(127.0.0.1:3306)/hello"
func SqlConnect(dsn string) *MySQLClient {
	client, ok := clients[dsn]

	if !ok {
		db, err := sql.Open("mysql", dsn)

		if err != nil {
			log.Panic(err)
			return nil
		}
		clients[dsn] = &MySQLClient{
			dsn:      dsn,
			database: db,
		}
	}
	return client
}

func (c MySQLClient) Query(query string, args ...interface{}) error {
	rows, err := c.database.Query(query, args...)
	if err != nil {
		return err
	}

	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	vals := make([]interface{}, len(cols))
	for i := range cols {
		vals[i] = new(sql.RawBytes)
	}

	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(vals...)
		if err != nil {
			return err
		}
	}

	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

func (c MySQLClient) Insert(query string) (sql.Result, error) {
	res, err := c.database.Exec(query)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c MySQLClient) Update(query string) (sql.Result, error) {
	res, err := c.database.Exec(query)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c MySQLClient) Delete(query string) error {
	_, err := c.database.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func (c MySQLClient) Close() {
	c.database.Close()
}

func (c MySQLClient) Ping() (bool, error) {
	err := c.database.Ping()
	if err != nil {
		return false, err
	}
	return true, nil
}
