package filesystem

import "time"

// timeoutAfterSeconds da una señal tras n segundos. Los tests de terminación lo
// usan para distinguir "tardó mucho" de "no termina nunca".
func timeoutAfterSeconds(n int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(n) * time.Second)
		close(ch)
	}()
	return ch
}
