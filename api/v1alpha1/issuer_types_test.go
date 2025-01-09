/*
Copyright © 2024 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestIssuerStatus_SetCondition_NewCondition(t *testing.T) {
	ctx := ctrl.LoggerInto(context.Background(), log.Log)
	issuerStatus := &IssuerStatus{} // no conditions initially

	issuerStatus.SetCondition(ctx, IssuerConditionReady, ConditionTrue, "InitialReason", "InitialMessage")

	assert.Len(t, issuerStatus.Conditions, 1, "Expected exactly one condition to be set.")
	cond := issuerStatus.Conditions[0]
	assert.Equal(t, IssuerConditionReady, cond.Type)
	assert.Equal(t, ConditionTrue, cond.Status)
	assert.Equal(t, "InitialReason", cond.Reason)
	assert.Equal(t, "InitialMessage", cond.Message)
	assert.NotNil(t, cond.LastTransitionTime, "LastTransitionTime should be set for a new condition.")
}

func TestIssuerStatus_SetCondition_UpdateConditionStatus(t *testing.T) {
	ctx := ctrl.LoggerInto(context.Background(), log.Log)
	now := v1.Now()

	issuerStatus := &IssuerStatus{
		Conditions: []IssuerCondition{
			{
				Type:               IssuerConditionReady,
				Status:             ConditionFalse,
				LastTransitionTime: &now, // simulate an existing condition with some prior time
				Reason:             "OldReason",
				Message:            "OldMessage",
			},
		},
	}

	issuerStatus.SetCondition(ctx, IssuerConditionReady, ConditionTrue, "NewReason", "NewMessage")

	assert.Len(t, issuerStatus.Conditions, 1)
	cond := issuerStatus.Conditions[0]
	assert.Equal(t, IssuerConditionReady, cond.Type)
	assert.Equal(t, ConditionTrue, cond.Status)
	assert.Equal(t, "NewReason", cond.Reason)
	assert.Equal(t, "NewMessage", cond.Message)

	// LastTransitionTime should be updated because status changed from ConditionFalse -> ConditionTrue
	assert.True(t, cond.LastTransitionTime.Time.After(now.Time), "LastTransitionTime should be more recent if the status changed.")
}

func TestIssuerStatus_SetCondition_NoStatusChange(t *testing.T) {
	ctx := ctrl.LoggerInto(context.Background(), log.Log)
	oldTime := v1.NewTime(time.Now().Add(-10 * time.Minute))

	issuerStatus := &IssuerStatus{
		Conditions: []IssuerCondition{
			{
				Type:               IssuerConditionReady,
				Status:             ConditionTrue,
				LastTransitionTime: &oldTime,
				Reason:             "ExistingReason",
				Message:            "ExistingMessage",
			},
		},
	}

	issuerStatus.SetCondition(ctx, IssuerConditionReady, ConditionTrue, "UpdatedReason", "UpdatedMessage")

	assert.Len(t, issuerStatus.Conditions, 1)
	cond := issuerStatus.Conditions[0]
	assert.Equal(t, IssuerConditionReady, cond.Type)
	assert.Equal(t, ConditionTrue, cond.Status)

	// Because status didn't actually change (still ConditionTrue),
	// LastTransitionTime should NOT be updated.
	assert.Equal(t, oldTime.Time, cond.LastTransitionTime.Time, "LastTransitionTime should remain unchanged if status didn't change.")

	// However, reason and message should be updated.
	assert.Equal(t, "UpdatedReason", cond.Reason)
	assert.Equal(t, "UpdatedMessage", cond.Message)
}

func TestIssuerStatus_HasCondition(t *testing.T) {
	issuerStatus := &IssuerStatus{
		Conditions: []IssuerCondition{
			{
				Type:   IssuerConditionReady,
				Status: ConditionTrue,
			},
			{
				Type:   IssuerConditionSupportsMetadata,
				Status: ConditionFalse,
			},
		},
	}

	assert.True(t, issuerStatus.HasCondition(IssuerConditionReady, ConditionTrue), "Should find Ready=True condition.")
	assert.False(t, issuerStatus.HasCondition(IssuerConditionReady, ConditionFalse), "Ready=False does not exist.")
	assert.True(t, issuerStatus.HasCondition(IssuerConditionSupportsMetadata, ConditionFalse), "Should find SupportsMetadata=False condition.")
	assert.False(t, issuerStatus.HasCondition(IssuerConditionSupportsMetadata, ConditionTrue), "SupportsMetadata=True does not exist.")
	assert.False(t, issuerStatus.HasCondition("NonExistent", ConditionTrue), "Non-existent type should be false.")
}

func TestIssuerStatus_UnsetCondition(t *testing.T) {
	issuerStatus := &IssuerStatus{
		Conditions: []IssuerCondition{
			{
				Type:   IssuerConditionReady,
				Status: ConditionTrue,
			},
			{
				Type:   IssuerConditionSupportsMetadata,
				Status: ConditionFalse,
			},
		},
	}

	issuerStatus.UnsetCondition(IssuerConditionReady)

	assert.Len(t, issuerStatus.Conditions, 1, "Expected to remove 1 condition.")
	assert.Equal(t, IssuerConditionSupportsMetadata, issuerStatus.Conditions[0].Type, "SupportsMetadata should remain.")

	// Trying to unset a condition that no longer exists should do nothing
	issuerStatus.UnsetCondition(IssuerConditionReady)
	assert.Len(t, issuerStatus.Conditions, 1, "No further removal should occur for missing condition.")
}

func TestIssuerStatus_UnsetCondition_NoConditions(t *testing.T) {
	issuerStatus := &IssuerStatus{}

	issuerStatus.UnsetCondition(IssuerConditionReady)

	assert.Empty(t, issuerStatus.Conditions, "No conditions to remove, so it should remain empty.")
}

func TestIssuerStatus_SetCondition_AddsNewConditionIfNotFound(t *testing.T) {
	ctx := ctrl.LoggerInto(context.Background(), log.Log)
	issuerStatus := &IssuerStatus{
		Conditions: []IssuerCondition{
			{
				Type:   IssuerConditionReady,
				Status: ConditionTrue,
			},
		},
	}

	issuerStatus.SetCondition(ctx, IssuerConditionSupportsMetadata, ConditionFalse, "SomeReason", "SomeMessage")

	assert.Len(t, issuerStatus.Conditions, 2, "Expected a new condition to be appended.")

	newCond := issuerStatus.Conditions[1]
	assert.Equal(t, IssuerConditionSupportsMetadata, newCond.Type)
	assert.Equal(t, ConditionFalse, newCond.Status)
	assert.Equal(t, "SomeReason", newCond.Reason)
	assert.Equal(t, "SomeMessage", newCond.Message)
	assert.NotNil(t, newCond.LastTransitionTime, "Newly added condition should set LastTransitionTime.")
}
