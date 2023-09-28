"""

    Configuration extractor for AgentTesla Payload (Discord/Telegram Variant)
    
    Author: Matthew @Embee_research
    Twitter: @embee_research

    Inspiration: https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor
    
    Sample Hashes (More at end of script)
    
    0de25252f312735c0a26f7ac7a27cc8a51bfcdd900fc2e8d0a8b65013988e7e9
    118a34bf096f5b9ea16c31de288793192ed4bc413ee8f50198eb7df7f5cf8f0e
    146f7c98ee50fd6022a139ec822b4a50b906fe141695c3bd479f3d90e3ecbe15
    16a976bb432be2baaaa0f6d32dbcbb00b823746a35561e3e8708bf0312515ed4
    
    Usage:
    Print C2: agentTesla-config-extractor.py -f <filename> 
    Print all strings: agentTesla-config-extractor.py -f <filename> --allstrings True


    The script works by
    - Locating decryption function via parameter/returntype signature
    - Locating metadatatoken of decryption function (avoids issues with names/obfuscation)
    - Locating all calls to decryption function and relevant offsets/keys
    - Removing any false values
    - Invoking the decryption method with all obtained values
    - Filtering returned values for c2-like data


"""




import clr, os, System,base64,sys,argparse
from statistics import median

parser =  argparse.ArgumentParser(description="Extract config from AgentTesla Payloads")
parser.add_argument('-f', '--file', required=False, help="Path to agentTesla file")
parser.add_argument('-d', '--dnlib', required=False, default="dnlib.dll",help="Path to dnlib file")
parser.add_argument('--allstrings', required=False, default=False, help="print all strings for files, not just c2")

args = parser.parse_args()


clr.AddReference("System")
clr.AddReference(os.getcwd() + "\\" + args.dnlib)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes
from System import Int32

debug = False



def get_agentTesla_ldc_values(module):
    #Get all offsets needed to call decryption method
    #These are typically stored in ldc_i4 IL instructions
    #Only ldc values that are prior to a call will be stored
    values = []
    for types in module.GetTypes():
        for method in types.Methods:
            if method.HasBody:
                for instr in method.Body.Instructions:
                    ins = method.Body.Instructions
                    i = 0
                    if instr.OpCode == OpCodes.Ldc_I4:
                        if ins[i+1].OpCode == OpCodes.Call:
                            operand = instr.Operand
                            if operand not in values:
                                values.append(operand)                       
                    i += 1       
    return values

def get_agentTesla_decrypt_method(module):
    #Retrieves the metadata token of the decryption method
    #Uses a hardcoded signature of (int32 in, system.string out)
    #I did not have issues with multiple signature hits, 
    #Script may need to be updated if clashes occur
    tokens = []
    
    
    #Enumerate module for target method
    for types in module.GetTypes():
        for method in types.GetMethods():
            params = method.GetParameters()
            if len(params) == 1:
                if params[0].ParameterType.FullName == "System.Int32":
                    if method.ReturnType.FullName == "System.String":  
                        tokens.append(method.MetadataToken)
    return tokens


def clean_values(values):
    #Remove ldc values that are out of range of expected values
    #Out of range values will cause memory access violations when the decryption method is called
    new_values = []
    val_median = round(median(values))
    #Allow for variance of 10%
    variance = val_median * 0.1
    #Filter values outside of variance
    for value in values:
        if abs(value) > (val_median + variance):
            continue
        if abs(value) < (val_median - variance):
            continue
        new_values.append(value)
    #Return cleaned values
    return new_values
    


def get_config(filename):
    #Open the file
    try:
        filename = os.getcwd()+"\\" + filename
        
    except:
        print("Unable to Open: " + filename)
        sys.exit(1)
        
    #Load the malware file as a "normal" reflection
    #This is needed for file execution
    ref_module = System.Reflection.Assembly.LoadFile(filename)
    #Load the malware module for dnlib
    #this is needed for IL enumeration
    dn_module = ModuleDefMD.Load(filename)
    #Obtain metadata token of decryption method
    mdtokens = get_agentTesla_decrypt_method(ref_module)
    #obtain all offsets for decryption method
    ldc_values = get_agentTesla_ldc_values(dn_module)
    ldc_values = clean_values(ldc_values)
    dec_strings = []
    
    
    for token in mdtokens:
        for key in ldc_values:
            try:
                #Convert key to System.Int32
                key = Int32(key)
                #Obtain the method using metadata token
                method = ref_module.ManifestModule.ResolveMethod(token)
                #Invoke the method with string offset. 
                out = method.Invoke(None, (key,))
                dec_strings.append(out)
            except:
                continue

    if not args.allstrings:
        for string in dec_strings:
            if len(string) > 12:
                if "http" in string:
                    if "dyn.com" not in string:
                        if "ipify.org" not in string:
                            return string
                            
    if args.allstrings:
        return dec_strings
    
    return None



####################################################################
        
if __name__ == "__main__":

    if args.file:
        try:
            c2 = get_config(args.file)
            print(args.file + ": " + str(c2))
        except Exception as e:
            #print(e)
            pass
            
    



"""
Verified Hashes
0de25252f312735c0a26f7ac7a27cc8a51bfcdd900fc2e8d0a8b65013988e7e9
118a34bf096f5b9ea16c31de288793192ed4bc413ee8f50198eb7df7f5cf8f0e
146f7c98ee50fd6022a139ec822b4a50b906fe141695c3bd479f3d90e3ecbe15
16a976bb432be2baaaa0f6d32dbcbb00b823746a35561e3e8708bf0312515ed4
17d374210ab665bff4abd342a9e54635f90481f9371b3d6aabca860bdbef7706
1a41302c041856d88ac470f964a874fc89c33b2fe7a3312f5720a01a66f09f1c
1ab5337bd3b76b84686c2aa616eb7e9639608a702be70da1a566128d4e36147d
1f0035845553e0069e22c4f16f058d537b0571339c9df9d8926f6edb67426f35
20ee6aa728dee4381f4a9e1cb68f2881c1cf49d433bc831b1522eb610e47c636
29fe6fff0874c8fdf094427fb99d3308d5e24528d788aae87b9f3b00bb70c93a
2a39b0b1adaf927a0ea6898da6eb77736713ee6185731a9f9a060f097705a184
2bb9e94737d0ef78b974ec601779bb2efd30ecde734f8640ad4e0e1d86efe97b
308f90718012b047a2ee3b2ae76a16dddb657537dbd61e2a43ee2bb17725c6a0
33b8648f67e3735ba82a7ae93c94680b9d1676214e44b3f3c5e44e1ebcf95299
3479a61e5df7c0f82d1392647da45b9d7078a4349e4b57e7076fa607b0f757e1
34cffb752ed7c3c21668ae30c2d24159ce479b26600a0506430b3a02bf814a52
3a97be528a2e9c892ad40865a97efec10333ad678be2aebe653fdcfbc1e505bc
405f204a0f233ddffb6984a37c30803b1e2877aea0e3a8ea74e308752a5e0fad
54df537c392c1eb689ecdbc50435b4ae8d26214f09b0d758ca886c7c608e5be8
5bddcbb9278d33d95600b0ff378f5f7fff986615ba1cb1ad4b538865e8c34afd
5c19d49626511a144b7d73ed111952cd5c9ed79ebb93347b78b753733fa17003
60af682b7e56dec78cce3ebd93b43b4ce6f85a9842c48dbab9d9282b7fec1d9b
60c5ef3af7a3b790a403a31630ce8c27a43d21727823f6e010cbbdf2ea0e0a35
63423d06c77c3526d9820f5caeebb4ddf986c89d39ef56698b8ac0eb28b0cccd
65e27a76da50e9f988bcf7cb142d24c5bc31dfd3f1b21012a7f655ddb1337cc5
6a41af11cfbe01403198b7b6dec0ea1f51ea851fbcc71f1e8bdcb2a353b65412
6d77d5a103439701f62301a640447eae7a8fd0a48b7a6e23ed47b1bf02c17b89
6fca0cc791b0beccdb8eee1883974c9842a08f3edf6af558680368ebad69a506
73d782dc28a38a6e4ee9680f3caee329106a4927433cb0b39837a6ab078f4065
7ac566649f88ff12127d3efa36fe4f16ce30efb840560194cc39fd487e860aae
7cae9baa6bae421e198634dbfe9bd7b873dcdd764fb2e68e21a89fe648be1bbd
7d5021ed24bc3bb6b5b029d0ab5ed36fccfe1e8511bbd90e4e3d3021f084de6b
7f2ce177a386c4702f9cefc501c41fafa818323a42b45cdc68f7fe365644a3ef
83cc9c4fec8f02105a5fc2a0854a0e7c7964d49d1b717cc31fdeba8525059e0a
91970dd848a42a1df4d798ab3a8e49fa3632b89637c2a0780bf37f6553bca91e
93e0b49ba883386f4aa0903e5086d001565c1c6ccd28897b24b326139600b2df
950f6e9d72c2968b9139375a0c8a6c65a8df2eab98879114293ae447ec0ad579
95dd113d2239a754fd3e2a8314429df25ae396aeeed43029292df04e830338f6
9c4ca913f311967f3e34bcb1bc2db41915d5ceb9b3b6165de8854913124ec3ff
9d20eabc91ae98403179116356bf8ee33b61c16dc5ded8a0fdc9a2bef44fd472
9ed966687e6219eb65f951d738006be8c20223db090212a35ee44b336cc1a2de
a3fa4673cd6c6efd251f3feed41ef88aa1721ba61d9a93936bdb75581e27033c
a645509dfc38de301048514cb6dcc0a5900b0162848b37f857c262b6b9de6075
a957401d332c850cd26b4d526251e1c37304946b28243f165bc9c48a0ff0af8e
b412458728b0c47c4ca1fb1eb6d4a99f752857ea83f5be07842936a641ad2cc6
bcb8fa0446a7d52e8bf88ba29faf124ac5ca677b3806aef9ca738855900a8672
c1fe8d3badc688c0a05257a8286549248e31915ec69c0025485ab2a63b8a243a
c5b726402d9ab379a66d4cc3236f971edc3eb16951d0999ffc5b7b117714543b
cb2f1dc8a293bcdc724d776948feb47289896b1ea76bda4500de1483383279d7
ccaeea59c0a7db1fd32814772a8a683c0b8d32cbe02214eac8f5d338b0576bd8
d16462832fc40981a65dbfb90cd6886c6b60185c9ea83f0c96ea7bf463430f90
d3c0f8d7e5eff92fb6378a1ccc62c8aba3944d12ccaade18fda748c9a7f0ecf7
d43fb23dc98239df82f9c9b8c8935f3d3222eaed80bbf7a64737d79c8385f6df
d963f7bb5f33b85387b27c90413d27d5a810d5727b2860522a7b3fffa9afe4c0
d9c9253f2bff48f4033711d9376b1ce9e4d77f1dd35f3d835e32198cfd53905b
dfc091425ac76ddbbcf1f0859cc1faf689bd6141b947115f9e7c2fc898270559
e094490b16494354c1332782d00b85cb21512ac58935d6e11faf8a015cbe7086
e479268915c1929ff1016e3bf9a5203ea5ab6475d89f5fcb4a1512d106f2caae
e5da9ecb7c72b39e7ae54d6abc896012ab04a19b1b2da997a843e8b167f80c18
e8f0db565edc47843e5ac9750b53b93e0d9d3dec51fcf0ba9368342e6bfc4359
ec6611fea9635a686e95a3f1fe226d624c7f4ae3c69c432b1ab9c720d7746a9b
ec6699793cc1fd02dc94366bcc4051b7c54228489bec09ed0b8a63f3bf4f79af
ee3126ca31a8d48b8bb63964d87788244da3bec19a31b11c29c82bfc56b12c41
eee101d8fb3953337c07e7de4a2b25693423722677bd4590428de4a8e37fa1cf
f294476af52a54d317743b608f7c5fa3ca9a3dad695bc4166ca561b40c556c22
fc08ab59267b999159f4399bc6d41204946a9f5a27cc38c5fe3b7d07d4f07c11
fc37ae98ebce49b3abfa919860f5d563bf84cd398f772d955158ac45ba6adc09
fddf39bac09c38759ad30c2b52cfd8fbc11dc4b263bfbb054808bee627b14684

"""