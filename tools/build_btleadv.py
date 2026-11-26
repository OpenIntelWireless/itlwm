#!/usr/bin/env python3
"""Build IntelBTPatcher.kext (the renamed BTLEAdvFixup implementation), the Lilu plugin that lets macOS start Bluetooth LE advertising on Intel controllers.

One build per macOS version, because the bluetoothd patterns are per build:
--target tahoe (macOS 26.7.1, default), --target sequoia (macOS 15.8.3) or --target sonoma (macOS 14.8.9)."""
import argparse,hashlib,os,plistlib,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NAME='IntelBTPatcher';VERSION='0.9.8';IDENT='org.forbiddenitlwm.'+NAME
def run(c): subprocess.run([str(x) for x in c],check=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    p.add_argument('--tree',type=Path,required=True,help='A folder holding MacKernelSDK and a DEBUG Lilu.kext (its Contents/Resources carries the Lilu SDK headers)')
    p.add_argument('--target',choices=('tahoe','sequoia','sonoma'),default='tahoe');a=p.parse_args()
    sdk=a.tree/'MacKernelSDK';lilu=a.tree/'Lilu.kext/Contents/Resources'
    base=FLAGS(sdk,lilu)+{'tahoe':[],'sequoia':['-DBTLEADV_SEQUOIA'],'sonoma':['-DBTLEADV_SONOMA']}[a.target]
    bundle=a.out/(NAME+'.kext')/'Contents';(bundle/'MacOS').mkdir(parents=True,exist_ok=True);objs=[]
    for s in (ROOT/'BTLEAdvFixup/kern_start.cpp',lilu/'Library/plugin_start.cpp'):
        o=a.out/(s.stem+'.o');run(base+['-DPRODUCT_NAME='+NAME,'-DMODULE_VERSION='+VERSION,'-c',s,'-o',o]);objs.append(o)
    exe=bundle/'MacOS'/NAME
    # The same source gives the same kext anywhere: ld's UUID otherwise mixes in the objects' times
    # (ZERO_AR_DATE) and their folder (-oso_prefix).
    subprocess.run([str(x) for x in ['xcrun','ld','-arch','x86_64','-kext','-undefined','dynamic_lookup','-no_fixup_chains','-macos_version_min','10.6',
                    '-oso_prefix',str(a.out.resolve())+'/','-o',exe,*objs,sdk/'Library/x86_64/libkmod.a']],
                   check=True,env=dict(os.environ,ZERO_AR_DATE='1'))
    run(['xcrun','strip','-S',exe])
    libs={x:'10.0.0' for x in ['com.apple.kpi.bsd','com.apple.kpi.dsep','com.apple.kpi.iokit','com.apple.kpi.libkern','com.apple.kpi.mach','com.apple.kpi.unsupported']}
    libs['as.vit9696.Lilu']='1.4.7'
    info=dict(CFBundleIdentifier=IDENT,CFBundleExecutable=NAME,CFBundleName=NAME,CFBundlePackageType='KEXT',CFBundleVersion=VERSION,CFBundleShortVersionString=VERSION,OSBundleCompatibleVersion=VERSION,OSBundleRequired='Root',OSBundleLibraries=libs,
      IOKitPersonalities={IDENT:dict(CFBundleIdentifier=IDENT,IOClass=NAME,IOMatchCategory=NAME,IOProviderClass='IOResources',IOResourceMatch='IOKit')})
    (bundle/'Info.plist').write_bytes(plistlib.dumps(info))
    syms=subprocess.check_output(['xcrun','nm',str(exe)],text=True);assert ' _kmod_info' in syms and ' __realmain' in syms
    undefined=subprocess.check_output(['xcrun','nm','-u',str(exe)],text=True)
    assert 'kern_start' not in undefined and 'kern_stop' not in undefined,'unresolved local lifecycle symbol'
    assert NAME+'_kern_start' in syms
    print('built',a.target,exe,hashlib.sha256(exe.read_bytes()).hexdigest())
def FLAGS(sdk,lilu):
    # The usual kernel C++ ABI choices for a Lilu plugin.
    return ['xcrun','clang++','-arch','x86_64','-std=c++17','-O2','-mkernel' if False else '-g','-fapple-kext','-fno-exceptions','-fno-rtti','-fno-stack-protector','-fno-builtin','-fno-asynchronous-unwind-tables','-mno-red-zone','-nostdinc','-DKERNEL','-DKERNEL_PRIVATE','-D__APPLE__','-D__MACH__','-I'+str(sdk/'Headers'),'-I'+str(lilu),'-I'+str(ROOT/'BTLEAdvFixup'),'-mmacosx-version-min=10.6','-DAPPLE_KEXT_ASSERTIONS=1','-DDRIVER_PRIVATE','-DAPPLE','-DNeXT','-fno-common','-fasm-blocks','-mmmx','-msse','-msse2','-msse3','-mssse3','-mfpmath=sse','-ftree-vectorize','-fno-non-call-exceptions','-Wall','-Wextra','-Wno-unused-parameter','-Wno-deprecated-declarations','-Wno-vla','-Wno-ossharedptr-misuse','-fdebug-compilation-dir=.','-ffile-prefix-map='+str(ROOT)+'=/itlwm','-ffile-prefix-map='+str(sdk)+'=/MacKernelSDK','-ffile-prefix-map='+str(lilu)+'=/Lilu']
if __name__=='__main__':main()
