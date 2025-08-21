BUILDDIR=.build
DEBBUILD=$(BUILDDIR)/debian
VERSION=0.0.0

clean:
	rm -rf $(BUILDDIR) || true

build-proxy-deb:
	mkdir -p $(DEBBUILD)
	cp -r packages/debian/vx-proxy $(DEBBUILD)
	mkdir -p $(DEBBUILD)/vx-proxy/usr/bin
	mkdir -p $(DEBBUILD)/vx-proxy/etc/vx-proxy
	go build -v -o $(DEBBUILD)/vx-proxy/usr/bin/vx-proxy -ldflags "-s -w" ./cmd/vx-proxy
	cp cmd/vx-proxy/vx-proxy.yml $(DEBBUILD)/vx-proxy/etc/vx-proxy/vx-proxy.yml
	echo "Version: $(VERSION)" >> $(DEBBUILD)/vx-proxy/DEBIAN/control
	chmod +x $(DEBBUILD)/vx-proxy/DEBIAN/postinst
	dpkg-deb -v --build --root-owner-group $(DEBBUILD)/vx-proxy

build-tools-deb:
	mkdir -p $(DEBBUILD)
	cp -r packages/debian/vx-tools $(DEBBUILD)
	mkdir -p $(DEBBUILD)/vx-tools/etc/vx-proxy
	go build -v -o $(DEBBUILD)/vx-tools/usr/bin/vx-dac-ctl -ldflags "-s -w" ./cmd/vx-dac-ctl
	go build -v -o $(DEBBUILD)/vx-tools/usr/bin/vx-static-auth -ldflags "-s -w" ./cmd/vx-static-auth
	cp cmd/vx-static-auth/vx-static-auth.yml $(DEBBUILD)/vx-tools/etc/vx-proxy/vx-static-auth.yml
	echo "Version: $(VERSION)" >> $(DEBBUILD)/vx-tools/DEBIAN/control
	dpkg-deb -v --build --root-owner-group $(DEBBUILD)/vx-tools
