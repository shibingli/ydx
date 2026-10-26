package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"strconv"

	"github.com/shibingli/ydx/errs"
)

// powAlgorithm is the algorithm name used by the built-in proof of work. | powAlgorithm 是内置工作量证明使用的算法名。
const powAlgorithm = "sha256"

// powSeedBytes is the entropy size of a PoW seed. | powSeedBytes 是 PoW 种子的熵大小。
const powSeedBytes = 16

// newPoWChallenge builds a scored proof-of-work request. | newPoWChallenge 构建按风险评分的工作量证明请求。
func (m *Manager) newPoWChallenge(score int) (*PoWChallenge, error) {
	difficulty := m.opts.PoW.Difficulty
	if score > m.opts.PoW.Threshold {
		difficulty += (score - m.opts.PoW.Threshold) / 10
	}
	if difficulty > m.opts.PoW.MaxDifficulty {
		difficulty = m.opts.PoW.MaxDifficulty
	}
	seed := make([]byte, powSeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, errs.Wrap(err, ErrProvider)
	}
	return &PoWChallenge{
		Algorithm:  powAlgorithm,
		Seed:       hex.EncodeToString(seed),
		Difficulty: difficulty,
	}, nil
}

// requiresPoW reports whether a challenge must carry proof of work. | requiresPoW 报告挑战是否必须携带工作量证明。
func (m *Manager) requiresPoW(score int) bool {
	switch m.opts.PoW.Mode {
	case PoWAlways:
		return true
	case PoWAdaptive:
		return score >= m.opts.PoW.Threshold
	default:
		return false
	}
}

// verifyPoW validates a proof against the issued challenge. | verifyPoW 校验针对已签发挑战的证明。
func verifyPoW(challenge *PoWChallenge, proof *PoWProof) error {
	if challenge == nil || proof == nil {
		return ErrPoWRequired
	}
	if challenge.Algorithm != powAlgorithm || challenge.Difficulty < 8 || challenge.Difficulty > 28 {
		return ErrPoWInvalid
	}
	seed, err := hex.DecodeString(challenge.Seed)
	if err != nil || len(seed) != powSeedBytes {
		return ErrPoWInvalid
	}
	message := challenge.Seed + ":" + strconv.FormatUint(proof.Nonce, 10)
	sum := sha256.Sum256([]byte(message))
	if !hasLeadingZeroBits(sum[:], challenge.Difficulty) {
		return ErrPoWInvalid
	}
	return nil
}

// hasLeadingZeroBits reports whether digest starts with bits zero bits. | hasLeadingZeroBits 报告摘要是否以 bits 个零位开头。
func hasLeadingZeroBits(digest []byte, count int) bool {
	if count <= 0 {
		return true
	}
	for _, b := range digest {
		if count >= 8 {
			if b != 0 {
				return false
			}
			count -= 8
			continue
		}
		return bits.LeadingZeros8(b) >= count
	}
	return false
}
