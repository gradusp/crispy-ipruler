package netlink

import (
	"github.com/vishvananda/netlink"
)

type (
	//Rule alias to netlink.Rule
	Rule = netlink.Rule

	//Rules alias to []netlink.Rule
	Rules = []netlink.Rule
)

var (
	//NewRule  alias to netlink.NewRule()
	NewRule = netlink.NewRule
)

//RuleList ...
func RuleList(family int) (Rules, error) {
	if ruleList != nil {
		return ruleList(family)
	}
	return nil, netlink.ErrNotImplemented
}

//RuleAdd ...
func RuleAdd(r *Rule) error {
	if ruleAdd != nil {
		return ruleAdd(r)
	}
	return netlink.ErrNotImplemented
}

//RuleDel ...
func RuleDel(r *Rule) error {
	if ruleDel != nil {
		return ruleDel(r)
	}
	return netlink.ErrNotImplemented
}

var (
	ruleList func(family int) (Rules, error)
	ruleAdd  func(r *Rule) error
	ruleDel  func(r *Rule) error
)
