package server

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log/syslog"
	"quicksilver/stub"
	"time"

	"github.com/openstack/swift/go/hummingbird"
)

type UploadServerHandler struct {
	logger   *syslog.Writer
	logLevel string
}

func NewUploadServerHandler() *UploadServerHandler {
	handler := &UploadServerHandler{}
	handler.logger = hummingbird.SetupLogger("LOG_LOCAL2", "quicksilver-server", "")
	handler.logLevel = "INFO"
	return handler
}

func (h *UploadServerHandler) Upload(img *stub.Image) (r string, err error) {
	start := time.Now()

	if int32(len(img.Content)) != img.Size {
		return "", errors.New("content size is not matched")
	}

	checksum := md5.Sum(img.Content)
	h.logger.Info(fmt.Sprintf("%s - - [%s] \"%s %s\" %d %s \"%s\" \"%s\" \"%s\" %.4f \"%s\"",
		//FIXME: it is not easy to extract client ip from thrift.
		//       try to do that later
		"0.0.0.0",
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		"PUT",
		"/sdb/20030/tenant000094/container0000/1470641940009738815",
		201,
		"0",
		"-",
		"-",
		"quicksilver-client",
		time.Since(start).Seconds(),
		"-"))

	return hex.EncodeToString(checksum[:]), nil
}
