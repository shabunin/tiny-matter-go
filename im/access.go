package im

// Privilege is an access control privilege (spec 9.10.5.2).
type Privilege uint8

const (
	View       Privilege = 1
	ProxyView  Privilege = 2
	Operate    Privilege = 3
	Manage     Privilege = 4
	Administer Privilege = 5
)

// Grants reports whether holding p grants want: Administer implies all,
// Manage implies Operate and View, Operate implies View.
func (p Privilege) Grants(want Privilege) bool {
	if p == want || p == Administer {
		return true
	}
	if p == ProxyView || want == ProxyView {
		return p == ProxyView && want == View
	}
	return p >= want
}

// PrivilegeInfo is implemented by clusters whose required privileges differ
// from the defaults (View to read, Operate to write and invoke).
type PrivilegeInfo interface {
	ReadPrivilege(attr uint32) Privilege
	WritePrivilege(attr uint32) Privilege
	InvokePrivilege(cmd uint32) Privilege
}

// AccessChecker decides whether the subject of ctx holds privilege p on a
// cluster instance.
type AccessChecker interface {
	Allowed(ctx *Context, endpoint uint16, cluster uint32, p Privilege) bool
}

func readPrivilege(c Cluster, attr uint32) Privilege {
	if pi, ok := c.(PrivilegeInfo); ok && !isGlobalAttribute(attr) {
		return pi.ReadPrivilege(attr)
	}
	return View
}

func writePrivilege(c Cluster, attr uint32) Privilege {
	if pi, ok := c.(PrivilegeInfo); ok {
		return pi.WritePrivilege(attr)
	}
	return Operate
}

func invokePrivilege(c Cluster, cmd uint32) Privilege {
	if pi, ok := c.(PrivilegeInfo); ok {
		return pi.InvokePrivilege(cmd)
	}
	return Operate
}

func (s *Server) allowed(ctx *Context, endpoint uint16, cluster uint32, p Privilege) bool {
	return s.Access == nil || s.Access.Allowed(ctx, endpoint, cluster, p)
}
