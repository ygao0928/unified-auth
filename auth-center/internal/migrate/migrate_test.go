package migrate

import (
	"testing"
)

func TestSplitSQLSkipsComments(t *testing.T) {
	got := splitSQL("-- hello\nCREATE TABLE t (id INT);\n\n-- trailing\nINSERT INTO t VALUES (1);\n")
	if len(got) != 2 || got[0] != "CREATE TABLE t (id INT)" || got[1] != "INSERT INTO t VALUES (1)" {
		t.Fatalf("%q", got)
	}
}

func TestMigrationNames(t *testing.T) {
	names, err := migrationNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "0001_init.sql" {
		t.Fatalf("%v", names)
	}
}
