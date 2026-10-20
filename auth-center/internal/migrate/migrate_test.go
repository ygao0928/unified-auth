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
	if len(names) != 4 || names[0] != "0001_init.sql" || names[1] != "0002_default_role.sql" || names[2] != "0003_backchannel_logout.sql" || names[3] != "0004_audit.sql" {
		t.Fatalf("%v", names)
	}
}
