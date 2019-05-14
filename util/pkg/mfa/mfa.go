package mfa

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "os"
  "time"
  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/session"
)

// TempCreds struct to formalize the pattern for storing creds
type TempCreds struct {
  SessionToken    string
  AccessKeyID     string
  SecretAccessKey string
  ExpiresAt       time.Time
}

// Returns the path to the credentials file
// Creates the file if it doesn't exist, verifies it's set up correctly
func getCacheFile(profile string) (string, error) {
  cacheDir := os.ExpandEnv("$HOME/.cache") + "/kops"
  err := os.MkdirAll(cacheDir, 0700)
  if err != nil {
    return "", err
  }

  return fmt.Sprintf("%s/%s-token.json", cacheDir, profile), nil
}

// Attempts to return the TempCreds stored in the cache
func getCache(profile string) (TempCreds, error) {
  cacheFile, err := getCacheFile(profile)
  if err != nil {
    return TempCreds{}, err
  }

  data, err := ioutil.ReadFile(cacheFile)
  if err != nil {
    return TempCreds{}, err
  }

  var creds TempCreds

  err = json.Unmarshal(data, &creds)
  if err != nil {
    return TempCreds{}, err
  }

  return creds, nil
}

// If the creds exist and can be retrieved, returns them and true
// Else, returns blank instance and false
func credsFromCache(profile string) (TempCreds, bool) {
  creds, err := getCache(profile)
  if err != nil {
    return TempCreds{}, false
  }

  if time.Since(creds.ExpiresAt) > 0 {
    return TempCreds{}, false
  }

  return creds, true
}

// Writes TempCreds to cache
func writeCache(creds TempCreds, profile string) (error) {
  cacheFile, err := getCacheFile(profile)
  if err != nil {
    return err
  }

  file, err := os.Create(cacheFile)
  if err != nil {
    return err
  }

  defer file.Close()

  encoder := json.NewEncoder(file)
  encoder.Encode(creds)
  return nil
}

// NewSession returns a new Session created from SDK defaults, config files,
// environment, and user provided config files. Once the Session is created
// it can be mutated to modify the Config or Handlers. The Session is safe to
// be read concurrently, but it should not be written to concurrently.
//
// If the AWS_SDK_LOAD_CONFIG environment variable is set to a truthy value
// the shared config file (~/.aws/config) will also be loaded in addition to
// the shared credentials file (~/.aws/credentials). Values set in both the
// shared config, and shared credentials will be taken from the shared
// credentials file. Enabling the Shared Config will also allow the Session
// to be built with retrieving credentials with AssumeRole set in the config.
//
// See the NewSessionWithOptions func for information on how to override or
// control through code how the Session will be created. Such as specifying the
// config profile, and controlling if shared config is enabled or not.
func NewSession(cfgs ...*aws.Config) (*session.Session, error) {

	return session.NewSession(cfgs...)
}

