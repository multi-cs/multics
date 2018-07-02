rm /root/Bureau/multics/*
make cleanall

make target=x32
cp x32/multics /root/Bureau/multics/multics.x32

make target=x64
cp x64/multics /root/Bureau/multics/multics.x64

make target=ppc
cp ppc/multics /root/Bureau/multics/multics.ppc

make target=mips
cp mips/multics /root/Bureau/multics/multics.mips

make target=sh4
cp sh4/multics /root/Bureau/multics/multics.sh4

make target=rpi
cp rpi/multics /root/Bureau/multics/multics.rpi

cp multics.cfg /root/Bureau/multics/

svn info | grep Revision >/root/Bureau/multics/Version

