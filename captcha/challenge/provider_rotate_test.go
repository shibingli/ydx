package challenge

import (
	"context"
	"math/rand/v2"
	"testing"
)

// rotateRecord generates one challenge and decodes its server answer. | rotateRecord 生成一次挑战并解码服务端答案。
func rotateRecord(t *testing.T) (*rotateProvider, *Record, rotateState) {
	t.Helper()
	p := newRotateProvider()
	generated, err := p.Generate(context.Background(), GenerateRequest{Width: 320, Height: 200, Locale: "en"})
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	var state rotateState
	if err := decodeAnswer(generated.Answer, &state); err != nil {
		t.Fatalf("decodeAnswer 失败: %v", err)
	}
	return p, &Record{Answer: generated.Answer}, state
}

// TestRotateRequiresInteractionTrack asserts the rotate challenge rejects a
// missing or too-short pointer track just like the slide challenge. |
// TestRotateRequiresInteractionTrack 断言旋转题与滑动题一样拒绝缺失或过短的轨迹。
func TestRotateRequiresInteractionTrack(t *testing.T) {
	p, record, state := rotateRecord(t)
	angle := state.Correction

	if result, err := p.Verify(context.Background(), record, Answer{Angle: &angle}); err != nil || result.Passed {
		t.Fatalf("空轨迹通过: %+v %v", result, err)
	}
	short := Answer{Angle: &angle, Track: Track{
		StartedAt: 0,
		EndedAt:   100,
		Points: []TrackPoint{
			{T: 0, X: 1, Y: 1},
			{T: 20, X: 2, Y: 2},
			{T: 40, X: 3, Y: 3},
			{T: 60, X: 4, Y: 4},
			{T: 80, X: 5, Y: 5},
			{T: 90, X: 6, Y: 6},
			{T: 95, X: 7, Y: 7},
			{T: 100, X: 8, Y: 8},
		},
	}}
	if result, err := p.Verify(context.Background(), record, short); err != nil || result.Passed {
		t.Fatalf("过短轨迹通过: %+v %v", result, err)
	}
	good := Answer{Angle: &angle, Track: goodTrack()}
	if result, err := p.Verify(context.Background(), record, good); err != nil || !result.Passed {
		t.Fatalf("合法轨迹被拒绝: %+v %v", result, err)
	}
}

// TestRotateAnswerSpaceIsHardToGuess asserts the correction covers the full
// 360 degrees and the tolerance is narrow enough that random guesses succeed
// only rarely. | TestRotateAnswerSpaceIsHardToGuess 断言校正角覆盖完整的 360 度，
// 且容差足够窄，使随机猜测极少成功。
func TestRotateAnswerSpaceIsHardToGuess(t *testing.T) {
	corrections := make([]int, 0, 120)
	for i := 0; i < 120; i++ {
		_, _, state := rotateRecord(t)
		if state.Tolerance != 3 {
			t.Fatalf("Tolerance = %d, 期望 3", state.Tolerance)
		}
		if state.Correction < 0 || state.Correction >= 360 {
			t.Fatalf("Correction = %d, 期望落在 [0,359]", state.Correction)
		}
		corrections = append(corrections, state.Correction)
	}
	low, high := false, false
	for _, c := range corrections {
		if c < 30 {
			low = true
		}
		if c >= 330 {
			high = true
		}
	}
	if !low || !high {
		t.Fatalf("校正角未覆盖 360 度: low=%v high=%v samples=%v", low, high, corrections)
	}

	// A random slider value is accepted only when it lands within three degrees
	// of the answer; 1000 samples keep this test far below a flaky pass rate. |
	// 随机滑块值只有落在答案 ±3 度内才会通过；1000 次采样远低于误报门槛。
	p, record, _ := rotateRecord(t)
	passes := 0
	for i := 0; i < 1000; i++ {
		angle := rand.IntN(360)
		result, err := p.Verify(context.Background(), record, Answer{Angle: &angle, Track: goodTrack()})
		if err != nil {
			t.Fatalf("Verify 失败: %v", err)
		}
		if result.Passed {
			passes++
		}
	}
	if passes > 50 {
		t.Fatalf("随机 1000 次猜测通过 %d 次，超过 5%% 上限", passes)
	}
}
