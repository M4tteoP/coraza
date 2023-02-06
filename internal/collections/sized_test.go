// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestSizedCollection(t *testing.T) {
	c1 := NewNamedCollection(variables.ArgsPost)
	c2 := NewNamedCollection(variables.ArgsGet)
	proxy := NewSizeCollection(variables.ArgsCombinedSize, c1, c2)

	assertValuesMatch(t, proxy.FindAll(), "0")
	c1.Set("key1", []string{"value1", "value2"})
	assertValuesMatch(t, proxy.FindAll(), "12")
	c1.Set("key2", []string{"value2"})
	assertValuesMatch(t, proxy.FindAll(), "18")
	c2.Set("key3", []string{"value3"})
	assertValuesMatch(t, proxy.FindAll(), "24")
}
