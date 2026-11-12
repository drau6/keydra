package extractor

import (
	"encoding/base64"
	"strings"
	"testing"
)

func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + strings.Repeat("x", 20)
}

func TestExtractSupabase(t *testing.T) {
	anon := fakeJWT(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon"}`)
	svc := fakeJWT(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role"}`)
	other := fakeJWT(`{"sub":"123","role":"anon"}`) // not a Supabase token

	body := `createClient("https://abcdefghijklmnopqrst.supabase.co","` + anon + `");
	const admin="` + svc + `"; const x="` + other + `";
	supabase.from("profiles").select(); supabase.storage.from("avatars").upload();`

	c := Extract(body)
	if !c.HasSupabase() {
		t.Fatal("expected supabase config")
	}
	roles := map[string]bool{}
	for _, k := range c.SupabaseKeys {
		roles[k.Role] = true
	}
	if !roles[RoleAnon] || !roles[RoleServiceRole] || len(c.SupabaseKeys) != 2 {
		t.Errorf("unexpected keys: %+v", c.SupabaseKeys)
	}
	if len(c.Tables) != 1 || c.Tables[0] != "profiles" {
		t.Errorf("storage buckets must not be treated as tables, got %v", c.Tables)
	}
}

func TestExtractFirebase(t *testing.T) {
	body := `initializeApp({apiKey:"AIza` + strings.Repeat("A", 35) + `",projectId:"demo-app",` +
		`databaseURL:"https://demo-app-default-rtdb.firebaseio.com",storageBucket:"demo-app.appspot.com"});
		getDocs(collection(db,"orders")); firebase.firestore().collection("notes").get()`
	c := Extract(body)
	if !c.HasFirebase() {
		t.Fatal("expected firebase config")
	}
	if len(c.Collections) != 2 {
		t.Errorf("collections: %v", c.Collections)
	}
	if c.Firebase.ProjectIDs[0] != "demo-app" || c.Firebase.Buckets[0] != "demo-app.appspot.com" {
		t.Errorf("unexpected firebase config: %+v", c.Firebase)
	}
}

func TestMergeDeduplicates(t *testing.T) {
	a := Extract(`x.from("users")`)
	b := Extract(`y.from("users")`)
	if n := len(a.Merge(b).Tables); n != 1 {
		t.Fatalf("expected 1 table, got %d", n)
	}
}

func TestExtractNewBackends(t *testing.T) {
	body := `const c=new Client().setEndpoint("https://cloud.appwrite.io/v1").setProject("proj123");
	databases.listDocuments("db1","notes"); storage.listFiles("uploads");
	tablesDB.listRows({databaseId:"db2",tableId:"orders"}); tablesDB.listRows("db3","items");
	const pb=new PocketBase("https://pb.example.com"); pb.collection("posts").getList();
	const cx=new ConvexReactClient("https://happy-otter-123.convex.cloud");
	useQuery("tasks:list"); client.query("messages:recent")`
	c := Extract(body)

	if !c.HasAppwrite() || c.Appwrite.Projects[0] != "proj123" || c.Appwrite.Endpoints[0] != "https://cloud.appwrite.io/v1" {
		t.Errorf("appwrite: %+v", c.Appwrite)
	}
	if len(c.Appwrite.Collections) != 1 || c.Appwrite.Collections[0] != (DocRef{"db1", "notes"}) {
		t.Errorf("appwrite collections: %+v", c.Appwrite.Collections)
	}
	if len(c.Appwrite.Tables) != 2 {
		t.Errorf("appwrite tables: %+v", c.Appwrite.Tables)
	}
	if len(c.Appwrite.Buckets) != 1 || c.Appwrite.Buckets[0] != "uploads" {
		t.Errorf("appwrite buckets: %+v", c.Appwrite.Buckets)
	}
	if !c.HasPocketBase() || c.PocketBase[0] != "https://pb.example.com" {
		t.Errorf("pocketbase: %v", c.PocketBase)
	}
	if !c.HasConvex() || len(c.Convex.Functions) != 2 {
		t.Errorf("convex: %+v", c.Convex)
	}
}
