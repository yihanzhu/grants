package risk

import (
	"fmt"

	"github.com/yihanzhu/grants/internal/model"
)

// BroadTrustMin is how many known projects make a trusted folder broad.
const BroadTrustMin = 3

// AssessBroadTrust raises the risk of a trusted folder that holds many projects. The
// caller counts the projects (Assess sees one grant at a time and cannot): other
// trusted folders and git repositories inside the folder. Codex trust reaches every
// project inside, so it is high. Claude Code asks again for folders it has not seen,
// so the shared trust is medium. Grants that are not trusted folders, and counts
// below BroadTrustMin, are left alone.
func AssessBroadTrust(g *model.Grant, projects int) {
	if g.Kind != model.KindTrust || projects < BroadTrustMin {
		return
	}
	v := verdict{level: g.Risk.Level, reasons: append([]string(nil), g.Risk.Reasons...), set: g.Risk.Level != ""}
	if g.Agent == model.Codex {
		v.add(model.RiskHigh, fmt.Sprintf("every project inside inherits trust (%d projects)", projects))
	} else {
		v.add(model.RiskMedium, fmt.Sprintf("folders inside it share this trust (%d projects)", projects))
	}
	g.Risk = v.result()
}
