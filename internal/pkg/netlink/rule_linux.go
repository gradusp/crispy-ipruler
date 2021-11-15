package netlink

import (
	"github.com/vishvananda/netlink"
)

func init() {
	ruleList = netlink.RuleList
	ruleAdd = netlink.RuleAdd
	ruleDel = netlink.RuleDel
}
