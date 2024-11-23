package util

// Error handling
func OnError(err error) {
	if err != nil {
		panic(err)
	}
}
