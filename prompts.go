package main

import (
	"encoding/hex"
	"fmt"
	"github.com/manifoldco/promptui"
)

func PromptManagementKey() ([]byte, error) {
	const defaultManagementKey = "010203040506070801020304050607080102030405060708"

	prompt := promptui.Prompt{
		Label: "Yubikey Management Key (Leave blank for default)",
		Mask:  '*',
	}

	result, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	if len(result) <= 0 {
		return hex.DecodeString(defaultManagementKey)
	} else {
		return hex.DecodeString(result)
	}
}

func PromptStoringInAnotherKey() (bool, error) {
	prompt := promptui.Prompt{
		Label:     "Would you like to store your wallet in another Yubikey? This can not be done later.",
		IsConfirm: true,
		Default:   "N",
	}
	result, err := prompt.Run()
	return result == "Y", err
}

func WaitForNextYubikeyPrompt() error {
	prompt := promptui.Prompt{
		Label: "Please insert next Yubikey and hit enter.",
	}
	_, err := prompt.Run()
	return err
}

func PromptPin() (string, error) {
	validate := func(input string) error {
		if len(input) < 6 {
			return fmt.Errorf("PIN must be at least 6 characters")
		}
		return nil
	}
	prompt := promptui.Prompt{
		Label:    "Yubikey PIN",
		Mask:     '*',
		Validate: validate,
	}

	return prompt.Run()
}
