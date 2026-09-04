package corpora

import "encoding/base64"

func base64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
