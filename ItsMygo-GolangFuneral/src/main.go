package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
)

type CompileRequest struct {
    Env  map[string]string `json:"env"`
    Code string            `json:"code"`
}

func generateRandomHash() (string, error) {
    bytes := make([]byte, 128)
    _, err := rand.Read(bytes)
    if err != nil {
        return "", err
    }

    hash := sha256.Sum256(bytes)
    return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func ensureDir(dir string) error {
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        return os.MkdirAll(dir, os.ModePerm)
    }
    return nil
}

func compileHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        var req CompileRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>ERROR request</h1>")
            w.Write([]byte(responseHTML))
            return
        }

        fileHash, err := generateRandomHash()
        if err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>ERR generate filename</h1>")
            w.Write([]byte(responseHTML))

            return
        }

        userFileDir := "./userFile"
        if err := ensureDir(userFileDir); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>ERR generate DIR</h1>")
            w.Write([]byte(responseHTML))
            return
        }

        envFileName := fmt.Sprintf("%s/%s_env.json", userFileDir, fileHash)
        envData, _ := json.Marshal(req.Env)
        if err := ioutil.WriteFile(envFileName, envData, 0644); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>ERR write env</h1>")
            w.Write([]byte(responseHTML))
            return
        }

        codeFileName := fmt.Sprintf("%s/%s.go", userFileDir, fileHash)
        if err := ioutil.WriteFile(codeFileName, []byte(req.Code), 0644); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>ERR write MyGolang</h1>")
            w.Write([]byte(responseHTML))

            return
        }
        
        data, err := ioutil.ReadFile(envFileName)
        if err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>Error reading env.json</h1>")
            w.Write([]byte(responseHTML))
            return
        }
    
        var env map[string]string
        if err := json.Unmarshal(data, &env); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>Error parsing env.json</h1>")
            w.Write([]byte(responseHTML))
            return
        }
    
        for key, value := range env {
            os.Setenv(key, value)
        }

        outputPath := fmt.Sprintf("./userEXE/%s", fileHash)

        cmd := exec.Command("go", "build", "-o", outputPath, codeFileName)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
    
        if err := cmd.Run(); err != nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            responseHTML := fmt.Sprintf("<h1>Error executing go build</h1>")
            w.Write([]byte(responseHTML))
            return
        }

        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        responseHTML := fmt.Sprintf("<h1>Success!</h1>")
        w.Write([]byte(responseHTML))

    } else {
        http.Error(w, "Request Method ERR", http.StatusMethodNotAllowed)
    }
}

func mygoHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "./static/mygo.html")
}


func main() {

    http.HandleFunc("/compile", compileHandler)
    http.HandleFunc("/itsmygo", mygoHandler) 

    http.Handle("/", http.FileServer(http.Dir("./static")))

    fmt.Println("Server started at http://127.0.0.1:8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Println("Error starting server:", err)
    }
}
