package authorization

import (
	"log"

	mempg "github.com/fergusstrange/embedded-postgres"
	"github.com/jmoiron/sqlx"
)

func connect() (*sqlx.DB, error) {
	database := mempg.NewDatabase(mempg.DefaultConfig().Port(5432))
	if err := database.Start(); err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := database.Stop(); err != nil {
			log.Fatal(err)
		}
	}()

	db, err := sqlx.Connect("postgres", "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable")
	return db, err
}

type User struct {
	Email       string
	Permissions []string
}
