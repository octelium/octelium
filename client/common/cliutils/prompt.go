// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cliutils

import (
	"os"

	"github.com/manifoldco/promptui"
)

func NewPrompt(prompt string, isConfirm bool) *promptui.Prompt {
	templates := &promptui.PromptTemplates{
		Prompt: "{{ . | bold }} ",
	}

	return &promptui.Prompt{
		Label:     prompt,
		Templates: templates,
		IsConfirm: isConfirm,
	}

}

func RunPromptConfirm(prompt string) error {
	if os.Getenv("DEBIAN_FRONTEND") == "noninteractive" {
		return nil
	}

	if _, err := NewPrompt(prompt, true).Run(); err != nil {
		return err
	}

	return nil
}
