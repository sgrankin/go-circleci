package circleci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	// mux is the HTTP request multiplexer used with the test server.
	mux *http.ServeMux

	// client is the CircleCI client being tested.
	client *Client

	// server is a test HTTP server used to provide mock API responses.
	server *httptest.Server
)

func setup() {
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	url, err := url.Parse(server.URL)
	if err != nil {
		panic(fmt.Sprintf("couldn't parse test server URL: %s", server.URL))
	}

	client = &Client{BaseURL: url, Version: APIVersion11}
}

func teardown() {
	defer server.Close()
}

func testBody(t *testing.T, r *http.Request, want string) {
	t.Helper()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Errorf("error reading request body: %v", err)
	}
	if got := string(b); got != want {
		t.Errorf("request Body is %s, want %s", got, want)
	}
}

func testMethod(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if got := r.Method; got != want {
		t.Errorf("request method: %v, want %v", got, want)
	}
}

func testAPIError(t *testing.T, err error, statusCode int, message string) {
	t.Helper()
	if err == nil {
		t.Errorf("expected APIError but got nil")
	}
	switch err := err.(type) {
	case *APIError:
		want := &APIError{HTTPStatusCode: statusCode, Message: message}
		if !reflect.DeepEqual(err, want) {
			t.Errorf("error was %+v, want %+v", err, want)
		}
	default:
		t.Errorf("expected APIError but got %T: %+v", err, err)
	}
}

func testQueryIncludes(t *testing.T, r *http.Request, key, value string) {
	t.Helper()
	query := r.URL.Query()
	if len(query[key]) > 1 {
		t.Errorf("query parameter %s set with multiple values: %#v", key, query[key])
		return
	}
	got := r.URL.Query().Get(key)
	if got != value {
		t.Errorf("expected query to include: %s=%s, got %s=%s", key, value, key, got)
	}
}

func testHeader(t *testing.T, r *http.Request, header string, want string) {
	if got := r.Header.Get(header); got != want {
		t.Errorf("Header.Get(%q) returned %s, want %s", header, got, want)
	}
}

func TestClient_request(t *testing.T) {
	setup()
	defer teardown()
	client.Token = "ABCD"
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testHeader(t, r, "Accept", "application/json")
		testHeader(t, r, "Content-Type", "application/json")
		testQueryIncludes(t, r, "circle-token", "ABCD")
		fmt.Fprint(w, `{"login": "jszwedko"}`)
	})

	err := client.request(context.Background(), "GET", "/me", &User{}, nil, nil)
	if err != nil {
		t.Errorf(`Client.request("GET", "/me", &User{}, nil, nil) errored with %s`, err)
	}
}

func TestClientWithContext_request(t *testing.T) {
	setup()
	defer teardown()
	client.Token = "ABCD"
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 0*time.Microsecond)
	defer cancel()
	err := client.request(ctx, "GET", "/me", &User{}, nil, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Error(`Client.request("GET", "/me", &User{}, nil, nil) didn't cancel request on timeout`)
	}
}

func TestClient_requestOverridesCircleToken(t *testing.T) {
	setup()
	defer teardown()
	client.Token = "ABCD"
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testHeader(t, r, "Accept", "application/json")
		testHeader(t, r, "Content-Type", "application/json")
		testQueryIncludes(t, r, "circle-token", "ABCD")
		fmt.Fprint(w, `{"login": "jszwedko"}`)
	})
	values := url.Values{}
	values.Set("circle-token", "pre-existing")

	err := client.request(context.Background(), "GET", "/me", &User{}, values, nil)
	if err != nil {
		t.Errorf(`Client.request("GET", "/me", &User{}, nil, nil) errored with %s`, err)
	}
}

func TestClient_request_withDebug(t *testing.T) {
	setup()
	defer teardown()
	buf := bytes.NewBuffer(nil)
	client.Token = "ABCD"
	client.Debug = true
	client.Logger = log.New(buf, "", 0)
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testHeader(t, r, "Accept", "application/json")
		testHeader(t, r, "Content-Type", "application/json")
		testQueryIncludes(t, r, "circle-token", "ABCD")
		fmt.Fprint(w, `{"login": "jszwedko"}`)
	})

	err := client.request(context.Background(), "GET", "/me", &User{}, nil, nil)
	if err != nil {
		t.Errorf(`Client.request("GET", "/me", &User{}, nil, nil) errored with %s`, err)
	}

	output := buf.String()

	t.Logf("debug output:\n%s", output)
	if !strings.Contains(output, "request:") {
		t.Error(`expected "request:" to appear in debug output`)
	}
	if !strings.Contains(output, "HTTP/1.1") {
		t.Error(`expected http request to appear in debug output`)
	}

	if !strings.Contains(output, "response:") {
		t.Error(`expected "response:" to appear in debug output`)
	}
	if !strings.Contains(output, "HTTP/1.1 200 OK") {
		t.Error(`expected http request to appear in debug output`)
	}
}

func TestClient_request_unauthenticated(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message": "You must log in first"}`)
	})

	err := client.request(context.Background(), "GET", "/me", &User{}, nil, nil)
	testAPIError(t, err, http.StatusUnauthorized, "You must log in first")
}

func TestClient_request_noErrorMessage(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := client.request(context.Background(), "GET", "/me", &User{}, nil, nil)
	testAPIError(t, err, http.StatusInternalServerError, "")
}

func TestClient_Me(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"login": "jszwedko"}`)
	})

	me, err := client.Me(context.TODO())
	if err != nil {
		t.Errorf("Client.Me returned error: %v", err)
	}

	want := &User{Login: "jszwedko"}
	if !reflect.DeepEqual(me, want) {
		t.Errorf("Client.Me returned %+v, want %+v", me, want)
	}
}

func TestClient_ListProjects(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `[{"reponame": "foo"}]`)
	})

	projects, err := client.ListProjects(context.TODO())
	if err != nil {
		t.Errorf("Client.ListProjects() returned error: %v", err)
	}

	want := []*Project{{Reponame: "foo"}}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("Client.ListProjects() returned %+v, want %+v", projects, want)
	}
}

func TestClient_ListProjects_parseFeatureFlagsRaw(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `
		[{
			"reponame": "foo",
			"feature_flags": {
				"not-in-feature-flags": true
			}
		}]
		`)
	})

	projects, err := client.ListProjects(context.TODO())
	if err != nil {
		t.Errorf("Client.ListProjects() returned error: %v", err)
	}

	if projects[0].FeatureFlags.Raw()["not-in-feature-flags"] != true {
		t.Errorf("expected Client.ListProjects()[not-in-feature-flags] to be true, was %+v", projects[0].FeatureFlags.Raw()["not-in-feature-flags"])
	}
}

func TestClient_ListProjects_parseNullableFeatureFlags(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `
		[{
			"reponame": "foo",
			"feature_flags": {
				"memory-limit": "512MB",
				"fleet": "something"
			}
		}]
		`)
	})

	projects, err := client.ListProjects(context.TODO())
	if err != nil {
		t.Errorf("Client.ListProjects() returned error: %v", err)
	}

	if *projects[0].FeatureFlags.Fleet != "something" {
		t.Errorf("expected Client.ListProjects()[0].Fleet to be 'something', was %+v", projects[0].FeatureFlags.Fleet)
	}

	if *projects[0].FeatureFlags.MemoryLimit != "512MB" {
		t.Errorf("expected Client.ListProjects()[0].MemoryLimit to be '512MB', was %+v", projects[0].FeatureFlags.MemoryLimit)
	}
}

func TestClient_EnableProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/org-name/repo-name/enable", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
	})

	err := client.EnableProject(context.TODO(), VcsTypeGithub, "org-name", "repo-name")
	if err != nil {
		t.Errorf("Client.EnableProject() returned error: %v", err)
	}
}

func TestClient_DisableProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/org-name/repo-name/enable", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
	})

	err := client.DisableProject(context.TODO(), VcsTypeGithub, "org-name", "repo-name")
	if err != nil {
		t.Errorf("Client.EnableProject() returned error: %v", err)
	}
}

func TestClient_FollowProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/org-name/repo-name/follow", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"reponame": "repo-name"}`)
	})

	project, err := client.FollowProject(context.TODO(), VcsTypeGithub, "org-name", "repo-name")
	if err != nil {
		t.Errorf("Client.FollowProject() returned error: %v", err)
	}

	want := &Project{Reponame: "repo-name"}
	if !reflect.DeepEqual(project, want) {
		t.Errorf("Client.FollowProject() returned %+v, want %+v", project, want)
	}
}

func TestClient_UnfollowProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/org-name/repo-name/unfollow", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"reponame": "repo-name"}`)
	})

	project, err := client.UnfollowProject(context.TODO(), VcsTypeGithub, "org-name", "repo-name")
	if err != nil {
		t.Errorf("Client.UnfollowProject() returned error: %v", err)
	}

	want := &Project{Reponame: "repo-name"}
	if !reflect.DeepEqual(project, want) {
		t.Errorf("Client.UnfollowProject() returned %+v, want %+v", project, want)
	}
}

func TestClient_GetProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `[
			{"username": "jszwedko", "reponame": "bar"},
			{"username": "joe", "reponame": "foo"},
			{"username": "jszwedko", "reponame": "foo"}
		]`)
	})

	project, err := client.GetProject(context.TODO(), "jszwedko", "foo")
	if err != nil {
		t.Errorf("Client.GetProject returned error: %v", err)
	}

	want := &Project{Username: "jszwedko", Reponame: "foo"}
	if !reflect.DeepEqual(project, want) {
		t.Errorf("Client.GetProject(%+v, %+v) returned %+v, want %+v", "jszwedko", "foo", project, want)
	}
}

func TestClient_GetProject_noMatching(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `[
			{"username": "jszwedko", "reponame": "bar"}
		]`)
	})

	project, err := client.GetProject(context.TODO(), "jszwedko", "foo")
	if err != nil {
		t.Errorf("Client.GetProject returned error: %v", err)
	}

	if project != nil {
		t.Errorf("Client.GetProject(%+v, %+v) returned %+v, want %+v", "jszwedko", "foo", project, nil)
	}
}

func TestClient_GetProject_urlDecodeBranches(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		// using Fprintf instead Fprint because `go vet` complains about a possible intention to use a formatted string
		fmt.Fprintf(w, `[
			{"username": "jszwedko", "reponame": "bar", "branches": {"apiv1%%2E1": {}}}
		]`)
	})

	project, err := client.GetProject(context.TODO(), "jszwedko", "bar")
	if err != nil {
		t.Errorf("Client.GetProject returned error: %v", err)
	}

	_, ok := project.Branches["apiv1.1"]
	if !ok {
		t.Errorf("expected Client.GetProject(%+v, %+v) to return branches containing 'apiv1.1'  got %+v", "jszwedko", "foo", project.Branches)
	}
}

func TestClient_recentBuilds_multiPage(t *testing.T) {
	setup()
	defer teardown()

	requestCount := 0
	mux.HandleFunc("/recent-builds", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(200)
		switch requestCount {
		case 0:
			testQueryIncludes(t, r, "offset", "0")
			testQueryIncludes(t, r, "limit", "100")
			fmt.Fprintf(w, "[%s]", strings.Trim(strings.Repeat(`{"build_num": 123},`, 100), ","))
		case 1:
			testQueryIncludes(t, r, "offset", "100")
			testQueryIncludes(t, r, "limit", "99")
			fmt.Fprintf(w, "[%s]", strings.Trim(strings.Repeat(`{"build_num": 123},`, 99), ","))
		default:
			t.Errorf("Client.ListRecentBuilds(%+v, %+v) made more than two requests to /recent-builds", 199, 0)
		}
		requestCount++
	})

	builds, err := client.recentBuilds(context.Background(), "recent-builds", nil, 199, 0)
	if err != nil {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned error: %v", 199, 0, err)
	}

	if len(builds) != 199 {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned %+v results, want %+v", 199, 0, len(builds), 99)
	}
}

func TestClient_recentBuilds_multiPageExhausted(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/recent-builds", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testQueryIncludes(t, r, "offset", "0")
		testQueryIncludes(t, r, "limit", "100")
		fmt.Fprintf(w, "[%s]", strings.Trim(strings.Repeat(`{"build_num": 123},`, 50), ","))
	})

	builds, err := client.recentBuilds(context.Background(), "recent-builds", nil, 199, 0)
	if err != nil {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned error: %v", 199, 0, err)
	}

	if len(builds) != 50 {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned %+v results, want %+v", 199, 0, len(builds), 50)
	}
}

func TestClient_recentBuilds_multiPageNoLimit(t *testing.T) {
	setup()
	defer teardown()

	requestCount := 0
	mux.HandleFunc("/recent-builds", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(200)
		switch requestCount {
		case 0:
			testQueryIncludes(t, r, "offset", "0")
			testQueryIncludes(t, r, "limit", "100")
			fmt.Fprintf(w, "[%s]", strings.Trim(strings.Repeat(`{"build_num": 123},`, 100), ","))
		case 1:
			testQueryIncludes(t, r, "offset", "100")
			testQueryIncludes(t, r, "limit", "100")
			fmt.Fprintf(w, "[%s]", strings.Trim(strings.Repeat(`{"build_num": 123},`, 99), ","))
		default:
			t.Errorf("Client.ListRecentBuilds(%+v, %+v) made more than two requests to /recent-builds", -1, 0)
		}
		requestCount++
	})

	builds, err := client.recentBuilds(context.Background(), "recent-builds", nil, -1, 0)
	if err != nil {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned error: %v", -1, 0, err)
	}

	if len(builds) != 199 {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned %+v results, want %+v", -1, 0, len(builds), 199)
	}
}

func TestClient_ListRecentBuilds(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/recent-builds", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testQueryIncludes(t, r, "offset", "2")
		testQueryIncludes(t, r, "limit", "10")
		fmt.Fprint(w, `[{"build_num": 123}, {"build_num": 124}]`)
	})

	builds, err := client.ListRecentBuilds(context.TODO(), 10, 2)
	if err != nil {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned error: %v", 10, 2, err)
	}

	want := []*Build{{BuildNum: 123}, {BuildNum: 124}}
	if !reflect.DeepEqual(builds, want) {
		t.Errorf("Client.ListRecentBuilds(%+v, %+v) returned %+v, want %+v", 10, 2, builds, want)
	}
}

func TestClient_ListRecentBuildsForProject(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/foo/bar/tree/master", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testQueryIncludes(t, r, "filter", "running")
		testQueryIncludes(t, r, "offset", "0")
		testQueryIncludes(t, r, "limit", "10")
		fmt.Fprint(w, `[{"build_num": 123}, {"build_num": 124}]`)
	})

	call := "Client.ListRecentBuilds(foo, bar, master, running, 10, 0)"

	builds, err := client.ListRecentBuildsForProject(context.TODO(), VcsTypeGithub, "foo", "bar", "master", "running", 10, 0)
	if err != nil {
		t.Errorf("%s returned error: %v", call, err)
	}

	want := []*Build{{BuildNum: 123}, {BuildNum: 124}}
	if !reflect.DeepEqual(builds, want) {
		t.Errorf("%s returned %+v, want %+v", call, builds, want)
	}
}

func TestClient_ListRecentBuildsForProject_noBranch(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/foo/bar", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testQueryIncludes(t, r, "filter", "running")
		testQueryIncludes(t, r, "offset", "0")
		testQueryIncludes(t, r, "limit", "10")
		fmt.Fprint(w, `[{"build_num": 123}, {"build_num": 124}]`)
	})

	call := "Client.ListRecentBuilds(foo, bar, , running, 10, 0)"

	builds, err := client.ListRecentBuildsForProject(context.TODO(), VcsTypeGithub, "foo", "bar", "", "running", 10, 0)
	if err != nil {
		t.Errorf("%s returned error: %v", call, err)
	}

	want := []*Build{{BuildNum: 123}, {BuildNum: 124}}
	if !reflect.DeepEqual(builds, want) {
		t.Errorf("%s returned %+v, want %+v", call, builds, want)
	}
}

func TestClient_GetBuild(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/123", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"build_num": 123}`)
	})

	build, err := client.GetBuild(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.GetBuild(jszwedko, foo, 123) returned error: %v", err)
	}

	want := &Build{BuildNum: 123}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.GetBuild(jszwedko, foo, 123) returned %+v, want %+v", build, want)
	}
}

func TestClient_ListBuildArtifacts(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/123/artifacts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `[{"path": "/some/path"}]`)
	})

	artifacts, err := client.ListBuildArtifacts(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.ListBuildArtifacts(github, jszwedko, foo, 123) returned error: %v", err)
	}

	want := []*Artifact{{Path: "/some/path"}}
	if !reflect.DeepEqual(artifacts, want) {
		t.Errorf("Client.ListBuildArtifacts(github, jszwedko, foo, 123) returned %+v, want %+v", artifacts, want)
	}
}

func TestClient_ListTestMetadata(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/123/tests", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"tests": [{"name": "some test"}]}`)
	})

	metadata, err := client.ListTestMetadata(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.ListTestMetadata(jszwedko, foo, 123) returned error: %v", err)
	}

	want := []*TestMetadata{{Name: "some test"}}
	if !reflect.DeepEqual(metadata, want) {
		t.Errorf("Client.ListTestMetadata(jszwedko, foo, 123) returned %+v, want %+v", metadata, want)
	}
}

func TestClient_Build(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/tree/master", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"build_num": 123}`)
	})

	build, err := client.Build(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "master")
	if err != nil {
		t.Errorf("Client.Build(jszwedko, foo, master) returned error: %v", err)
	}

	want := &Build{BuildNum: 123}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.Build(jszwedko, foo, master) returned %+v, want %+v", build, want)
	}
}

func TestClient_ParameterizedBuild(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/tree/master", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"build_parameters":{"param":"foo"}}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"build_num": 123}`)
	})

	params := map[string]string{
		"param": "foo",
	}

	build, err := client.ParameterizedBuild(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "master", params)
	if err != nil {
		t.Errorf("Client.Build(jszwedko, foo, master) returned error: %v", err)
	}

	want := &Build{BuildNum: 123}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.Build(jszwedko, foo, master) returned %+v, want %+v", build, want)
	}
}

func TestClient_BuildOpts(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/tree/master", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"build_parameters":{"param":"foo"},"revision":"SHA"}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"build_num": 123}`)
	})

	opts := map[string]interface{}{
		"build_parameters": map[string]string{
			"param": "foo",
		},
		"revision": "SHA",
	}

	build, err := client.BuildOpts(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "master", opts)
	if err != nil {
		t.Errorf("Client.Build(jszwedko, foo, master) returned error: %v", err)
	}

	want := &Build{BuildNum: 123}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.Build(jszwedko, foo, master) returned %+v, want %+v", build, want)
	}
}

func TestClient_BuildByProjectBranch(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/build", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"branch":"master"}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"status": 200, "body": "Build created"}`)
	})

	err := client.BuildByProjectBranch(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "master")
	if err != nil {
		t.Errorf("Client.BuildByProjectBranch(github, jszwedko, foo, master) returned error: %v", err)
	}
}

func TestClient_BuildByProjectRevision(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/build", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"revision":"SHA"}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"status": 200, "body": "Build created"}`)
	})

	err := client.BuildByProjectRevision(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "SHA")
	if err != nil {
		t.Errorf("Client.BuildByProjectRevision(github, jszwedko, foo, SHA) returned error: %v", err)
	}
}

func TestClient_BuildByProjectTag(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/build", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"tag":"v0.0.1"}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"status": 200, "body": "Build created"}`)
	})

	err := client.BuildByProjectTag(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "v0.0.1")
	if err != nil {
		t.Errorf("Client.BuildByProjectTag(github, jszwedko, foo, v0.0.1) returned error: %v", err)
	}
}

func TestClient_BuildByProject(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/build", func(w http.ResponseWriter, r *http.Request) {
		testBody(t, r, `{"branch":"pull/1234","revision":"8afbae7ec63b2b0f2886740d03161dbb08ba55f5"}`)
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"status": 200, "body": "Build created"}`)
	})

	opts := map[string]interface{}{
		"revision": "8afbae7ec63b2b0f2886740d03161dbb08ba55f5",
		"branch":   "pull/1234",
	}

	err := client.BuildByProject(context.TODO(), VcsTypeGithub, "jszwedko", "foo", opts)
	if err != nil {
		t.Errorf("Client.BuildByProjectTag(github, jszwedko, foo, opts) returned error: %v", err)
	}
}

func TestClient_RetryBuild(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/123/retry", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"build_num": 124}`)
	})

	build, err := client.RetryBuild(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.RetryBuild(jszwedko, foo, 123) returned error: %v", err)
	}

	want := &Build{BuildNum: 124}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.RetryBuild(jszwedko, foo, 123) returned %+v, want %+v", build, want)
	}
}

func TestClient_CancelBuild(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/123/cancel", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"build_num": 123}`)
	})

	build, err := client.CancelBuild(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.CancelBuild(jszwedko, foo, 123) returned error: %v", err)
	}

	want := &Build{BuildNum: 123}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.CancelBuild(jszwedko, foo, 123) returned %+v, want %+v", build, want)
	}
}

func TestClient_ClearCache(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/build-cache", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		fmt.Fprint(w, `{"status": "cache cleared"}`)
	})

	status, err := client.ClearCache(context.TODO(), VcsTypeGithub, "jszwedko", "foo")
	if err != nil {
		t.Errorf("Client.ClearCache(jszwedko, foo) returned error: %v", err)
	}

	want := "cache cleared"
	if !reflect.DeepEqual(status, want) {
		t.Errorf("Client.ClearCache(jszwedko, foo) returned %+v, want %+v", status, want)
	}
}

func TestClient_AddEnvVar(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/envvar", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testBody(t, r, `{"name":"bar","value":"baz"}`)
		fmt.Fprint(w, `{"name": "bar"}`)
	})

	status, err := client.AddEnvVar(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "bar", "baz")
	if err != nil {
		t.Errorf("Client.AddEnvVar(jszwedko, foo, bar, baz) returned error: %v", err)
	}

	want := &EnvVar{Name: "bar"}
	if !reflect.DeepEqual(status, want) {
		t.Errorf("Client.AddEnvVar(jszwedko, foo, bar, baz) returned %+v, want %+v", status, want)
	}
}

func TestClient_ListEnvVars(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/envvar", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testBody(t, r, "")
		fmt.Fprint(w, `[{"name": "bar", "value":"xxxbar"}]`)
	})

	status, err := client.ListEnvVars(context.TODO(), VcsTypeGithub, "jszwedko", "foo")
	if err != nil {
		t.Errorf("Client.ListEnvVars(jszwedko, foo) returned error: %v", err)
	}

	want := []EnvVar{
		{Name: "bar", Value: "xxxbar"},
	}

	if !reflect.DeepEqual(status, want) {
		t.Errorf("Client.ListEnvVars(jszwedko, foo) returned %+v, want %+v", status, want)
	}
}

func TestClient_DeleteEnvVar(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/envvar/bar", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.DeleteEnvVar(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "bar")
	if err != nil {
		t.Errorf("Client.DeleteEnvVar(jszwedko, foo, bar) returned error: %v", err)
	}
}

func TestClient_AddSSHKey(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/project/github/jszwedko/foo/ssh-key", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testBody(t, r, `{"hostname":"example.com","private_key":"some-key"}`)
		w.WriteHeader(http.StatusCreated)
	})

	err := client.AddSSHKey(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "example.com", "some-key")
	if err != nil {
		t.Errorf("Client.AddSSHKey(jszwedko, foo, example.com, some-key) returned error: %v", err)
	}
}

func TestClient_GetActionOutput(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/some-s3-path", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `[{"Message":"hello"}, {"Message": "world"}]`)
	})

	action := &Action{HasOutput: true, OutputURL: server.URL + "/some-s3-path"}

	outputs, err := client.GetActionOutputs(context.TODO(), action)
	if err != nil {
		t.Errorf("Client.GetActionOutput(%+v) returned error: %v", action, err)
	}

	want := []*Output{{Message: "hello"}, {Message: "world"}}
	if !reflect.DeepEqual(outputs, want) {
		t.Errorf("Client.GetActionOutput(%+v) returned %+v, want %+v", action, outputs, want)
	}
}

func TestClient_GetActionOutput_withDebug(t *testing.T) {
	setup()
	defer teardown()
	buf := bytes.NewBuffer(nil)
	client.Debug = true
	client.Logger = log.New(buf, "", 0)
	mux.HandleFunc("/some-s3-path", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `[{"Message":"hello"}, {"Message": "world"}]`)
	})

	action := &Action{HasOutput: true, OutputURL: server.URL + "/some-s3-path"}

	_, err := client.GetActionOutputs(context.TODO(), action)
	if err != nil {
		t.Errorf("Client.GetActionOutput(%+v) returned error: %v", action, err)
	}

	output := buf.String()

	t.Logf("debug output:\n%s", output)
	if !strings.Contains(output, "request:") {
		t.Error(`expected "request:" to appear in debug output`)
	}
	if !strings.Contains(output, "HTTP/1.1") {
		t.Error(`expected http request to appear in debug output`)
	}

	if !strings.Contains(output, "response:") {
		t.Error(`expected "response:" to appear in debug output`)
	}
	if !strings.Contains(output, "HTTP/1.1 200 OK") {
		t.Error(`expected http request to appear in debug output`)
	}
}

func TestClient_GetActionOutput_noOutput(t *testing.T) {
	setup()
	defer teardown()

	action := &Action{HasOutput: false}

	outputs, err := client.GetActionOutputs(context.TODO(), action)
	if err != nil {
		t.Errorf("Client.GetActionOutput(%+v) returned error: %v", action, err)
	}

	if outputs != nil {
		t.Errorf("Client.GetActionOutput(%+v) returned %+v: want %v", action, outputs, nil)
	}
}

func TestClient_GetActionOutput_withContext(t *testing.T) {
	setup()
	defer teardown()
	mux.HandleFunc("/some-s3-path", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `[{"Message":"hello"}, {"Message": "world"}]`)
	})

	action := &Action{HasOutput: true, OutputURL: server.URL + "/some-s3-path"}

	ctx, cancel := context.WithTimeout(context.Background(), 0*time.Microsecond)
	defer cancel()
	_, err := client.GetActionOutputs(ctx, action)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Client.GetActionOutput(%+v) should've returned context deadline error", action)
	}
}

func TestClient_ListCheckoutKeys(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/checkout-key", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `[{
			"public_key": "some public key",
			"type": "deploy-key",
			"fingerprint": "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
			"login": null,
			"preferred": true
		}]`)
	})

	checkoutKeys, err := client.ListCheckoutKeys(context.TODO(), VcsTypeGithub, "jszwedko", "foo")
	if err != nil {
		t.Errorf("Client.ListCheckoutKeys(jszwedko, foo) returned error: %v", err)
	}

	want := []*CheckoutKey{{
		PublicKey:   "some public key",
		Type:        "deploy-key",
		Fingerprint: "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
		Login:       nil,
		Preferred:   true,
	}}
	if !reflect.DeepEqual(checkoutKeys, want) {
		t.Errorf("Client.ListCheckoutKeys(jszwedko, foo) returned %+v, want %+v", checkoutKeys, want)
	}
}

func TestClient_CreateCheckoutKey(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/checkout-key", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testBody(t, r, `{"type":"github-user-key"}`)
		fmt.Fprintf(w, `{
			"public_key": "some public key",
			"type": "github-user-key",
			"fingerprint": "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
			"login": "jszwedko",
			"preferred": true
		}`)
	})

	checkoutKey, err := client.CreateCheckoutKey(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "github-user-key")
	if err != nil {
		t.Errorf("Client.CreateCheckoutKey(jszwedko, foo, github-user-key) returned error: %v", err)
	}

	username := "jszwedko"
	want := &CheckoutKey{
		PublicKey:   "some public key",
		Type:        "github-user-key",
		Fingerprint: "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
		Login:       &username,
		Preferred:   true,
	}
	if !reflect.DeepEqual(checkoutKey, want) {
		t.Errorf("Client.Client.CreateCheckoutKey(jszwedko, foo, github-user-key) returned %+v, want %+v", checkoutKey, want)
	}
}

func TestClient_GetCheckoutKey(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/checkout-key/37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `{
			"public_key": "some public key",
			"type": "deploy-key",
			"fingerprint": "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
			"login": null,
			"preferred": true
		}`)
	})

	checkoutKey, err := client.GetCheckoutKey(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2")
	if err != nil {
		t.Errorf("Client.GetCheckoutKey(jszwedko, foo, 37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2) returned error: %v", err)
	}

	want := &CheckoutKey{
		PublicKey:   "some public key",
		Type:        "deploy-key",
		Fingerprint: "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2",
		Login:       nil,
		Preferred:   true,
	}
	if !reflect.DeepEqual(checkoutKey, want) {
		t.Errorf("Client.GetCheckoutKey(jszwedko, foo, 37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2) returned %+v, want %+v", checkoutKey, want)
	}
}

func TestClient_DeleteCheckoutKey(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/checkout-key/37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		fmt.Fprintf(w, `{"message": "ok"}`)
	})

	err := client.DeleteCheckoutKey(context.TODO(), VcsTypeGithub, "jszwedko", "foo", "37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2")
	if err != nil {
		t.Errorf("Client.DeleteCheckoutKey(jszwedko, foo, 37:27:f7:68:85:43:46:d2:e1:30:83:8f:f7:1b:ad:c2) returned error: %v", err)
	}
}

func TestClient_AddSSHUser(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/project/github/jszwedko/foo/123/ssh-users", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"ssh_users": [{"github_id": 1234, "login": "jszwedko"}]}`)
	})

	build, err := client.AddSSHUser(context.TODO(), VcsTypeGithub, "jszwedko", "foo", 123)
	if err != nil {
		t.Errorf("Client.AddSSHUser(jszwedko, foo, 123) returned error: %v", err)
	}

	want := &Build{SSHUsers: []*SSHUser{{GithubID: 1234, Login: "jszwedko"}}}
	if !reflect.DeepEqual(build, want) {
		t.Errorf("Client.AddSSHUser(jszwedko, foo, 123) returned %+v, want %+v", build, want)
	}
}

func TestClient_AddHerokuKey(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/user/heroku-key", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testBody(t, r, `{"apikey":"53433a12-9c99-11e5-97f5-1458d009721"}`)
		fmt.Fprint(w, `""`)
	})

	err := client.AddHerokuKey(context.TODO(), "53433a12-9c99-11e5-97f5-1458d009721")
	if err != nil {
		t.Errorf("Client.AddHerokuKey(53433a12-9c99-11e5-97f5-1458d009721) returned error: %v", err)
	}
}

func TestClient_TriggerPipeline(t *testing.T) {
	setup()
	defer teardown()

	t.Run("should trigger a pipeline successfully", func(t *testing.T) {
		mux.HandleFunc("/project/github/mattermost/mattermod/pipeline", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "POST")
			testBody(t, r, `{"branch":"testbranch","parameters":{"tbs_pr":"bar","tbs_sha":"foo"}}`)
			fmt.Fprint(w, `{"id": "foo", "state": "running", "number": 1, "created_at": "2020-08-05T19:33:08Z"}`)
		})
		client.Version = APIVersion2
		defer func() {
			client.Version = APIVersion11
		}()

		params := map[string]interface{}{
			"tbs_pr":  "bar",
			"tbs_sha": "foo",
		}
		got, err := client.TriggerPipeline(context.TODO(), VcsTypeGithub, "mattermost", "mattermod", "testbranch", "", params)
		if err != nil {
			t.Errorf("Client.TriggerPipeline(mattermost, mattermod) returned error: %v", err)
			return
		}

		want := &Pipeline{
			ID:        "foo",
			State:     "running",
			Number:    1,
			CreatedAt: time.Date(2020, time.August, 5, 19, 33, 8, 0, time.UTC),
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Client.TriggerPipeline(mattermost, mattermod) returned %v, want %v", got, want)
		}
	})

	t.Run("should fail to trigger a pipeline if we pass both branch an tag params", func(t *testing.T) {
		client.Version = APIVersion2
		defer func() {
			client.Version = APIVersion11
		}()

		params := map[string]interface{}{
			"tbs_pr":  "bar",
			"tbs_sha": "foo",
		}
		_, err := client.TriggerPipeline(context.TODO(), VcsTypeGithub, "mattermost", "mattermod", "testbranch", "testtag", params)
		if err == nil {
			t.Errorf("Client.TriggerPipeline(mattermost, mattermod) should have returned error")
			return
		}
	})
}

func TestClient_GetPipelineWorkflow(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/pipeline/id/workflow", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"items": [{	"pipeline_id": "id", "canceled_by": "someone", "id": "foo", "name": "CI",    "project_slug": "github/mattermost/mattermod", "errored_by": "someone", "status": "success", "started_by": "someone", "pipeline_number": 0, "created_at": "2020-08-05T19:33:08Z", "stopped_at": "2020-08-05T19:33:08Z"}], "next_page_token": "token"}`)
	})
	client.Version = APIVersion2
	defer func() {
		client.Version = APIVersion11
	}()

	got, err := client.GetPipelineWorkflows(context.TODO(), "id", "")
	if err != nil {
		t.Errorf("Client.GetPipeline(id, \"\") returned error: %v", err)
		return
	}

	want := &WorkflowList{
		Items: []WorkflowItem{
			{
				PipelineID:     "id",
				CanceledBy:     "someone",
				ID:             "foo",
				Name:           "CI",
				ProjectSlug:    "github/mattermost/mattermod",
				ErroredBy:      "someone",
				Status:         WorkflowSuccess,
				StartedBy:      "someone",
				PipelineNumber: 0,
				CreatedAt:      time.Date(2020, time.August, 5, 19, 33, 8, 0, time.UTC),
				StoppedAt:      time.Date(2020, time.August, 5, 19, 33, 8, 0, time.UTC),
			},
		},
		NextPageToken: "token",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Client.GetPipeline(id, \"\") returned %+v, want %+v", got, want)
	}
}

func TestClient_GetPipelineByBranch(t *testing.T) {
	setup()
	defer teardown()

	t.Run("should get a pipeline successfully", func(t *testing.T) {
		mux.HandleFunc("/project/github/mattermost/mattermod/pipeline", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "GET")
			testQueryIncludes(t, r, "branch", "testbranch")
			fmt.Fprint(w, `{
"next_page_token": null,
"items": [
	{
		"id": "8c9c042e-c08d-4aa1-aee6-0f3810885b4e",
		"errors": [],
		"project_slug": "gh/mattermost/mattermod",
		"updated_at": "2021-05-11T14:50:47.741Z",
		"number": 24549,
		"state": "created",
		"created_at": "2021-05-11T14:50:47.741Z",
		"trigger": {
			"received_at": "2021-05-11T14:50:47.248Z",
			"type": "api",
			"actor": {
				"login": "mattermost-build",
				"avatar_url": "https://avatars.githubusercontent.com/u/10821961?v=4"
			}
		},
		"vcs": {
			"origin_repository_url": "https://github.com/mattermost/mattermod",
			"target_repository_url": "https://github.com/mattermost/mattermod",
			"revision": "f0b2f5fed6honk6911eafbc3bhonk1a2",
			"provider_name": "GitHub",
			"branch": "pull/17603"
		}
	}
]
}`)
		})
		client.Version = APIVersion2
		defer func() {
			client.Version = APIVersion11
		}()

		got, err := client.GetPipelinesForBranch(context.TODO(), VcsTypeGithub, "mattermost", "mattermod", "testbranch", "")
		if err != nil {
			t.Errorf("Client.GetPipelineByBranch(mattermost, mattermod) returned error: %v", err)
			return
		}

		want := &PipelineList{
			NextPageToken: "",
			Items: []PipelineItem{
				{
					ID:          "8c9c042e-c08d-4aa1-aee6-0f3810885b4e",
					ProjectSlug: "gh/mattermost/mattermod",
					UpdatedAt:   "2021-05-11T14:50:47.741Z",
					Number:      24549,
					State:       "created",
					CreatedAt:   "2021-05-11T14:50:47.741Z",
					Trigger: Trigger{
						ReceivedAt: "2021-05-11T14:50:47.248Z",
						Type:       "api",
						Actor: Actor{
							Login:     "mattermost-build",
							AvatarURL: "https://avatars.githubusercontent.com/u/10821961?v=4",
						},
					},
					Vcs: Vcs{
						OriginRepositoryURL: "https://github.com/mattermost/mattermod",
						TargetRepositoryURL: "https://github.com/mattermost/mattermod",
						Revision:            "f0b2f5fed6honk6911eafbc3bhonk1a2",
						ProviderName:        "GitHub",
						Branch:              "pull/17603",
					},
				},
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Client.TriggerPipeline(mattermost, mattermod) returned %v, want %v", got, want)
		}
	})
}

func TestClient_CancelWorkflow(t *testing.T) {
	setup()
	defer teardown()

	client.Version = APIVersion2
	defer func() {
		client.Version = APIVersion11
	}()

	t.Run("should cancel a workflow successfully", func(t *testing.T) {
		mux.HandleFunc("/workflow/123-abc-345/cancel", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "POST")
			fmt.Fprint(w, `{"message": "Accepted."}`)
		})

		build, err := client.CancelWorkflow(context.TODO(), "123-abc-345")
		if err != nil {
			t.Errorf("Client.CancelWorkflow returned error: %v", err)
		}

		want := &CancelWorkflow{Message: "Accepted."}
		if !reflect.DeepEqual(build, want) {
			t.Errorf("Client.CancelBuild returned %+v, want %+v", build, want)
		}
	})
}
