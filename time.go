package jwt

import (
	"encoding/json"
	"time"
)

// Time подменяет собой стандартное time.Time, но переопределяет для него
// формат представления и распаковки из JSON в виде числа. Во всем остальном
// ведет себя как стандартный time.Time.
type Time struct {
	time.Time
}

// UnmarshalJSON восстанавливает время, представленное в формате JSON в виде
// числа.
func (t *Time) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	t.Time = time.Unix(i, 0)
	return nil
}

// MarshalJSON представляет время в формате JSON в виде числа.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Unix())
}
