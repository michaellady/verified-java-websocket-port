package intake

func ValidateAutobahnDescriptor(descriptor ContainerDescriptor) error {
	exactReference := "docker.io/crossbario/autobahn-testsuite@" + AutobahnManifestDigest
	if descriptor.Reference != exactReference || descriptor.Platform != "linux/amd64" || descriptor.ManifestDigest != AutobahnManifestDigest || !validateDigest(descriptor.ConfigDigest) {
		return deny("CONTAINER_DESCRIPTOR_MISMATCH", "$.autobahn", "Autobahn must bind the exact linux/amd64 manifest descriptor")
	}
	return nil
}
