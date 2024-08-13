package softblake3

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

type testVec struct {
	inputLen  int
	hash      string
	keyedHash string
	deriveKey string
}

func (tv *testVec) input() []byte {
	out := make([]byte, tv.inputLen)
	for i := range out {
		out[i] = uint8(i % 251)
	}
	return out
}

const (
	testVectorKey     = "whats the Elvish word for friend"
	testVectorContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
)

var vectors = []testVec{
	{
		inputLen:  0,
		hash:      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
		keyedHash: "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f",
		deriveKey: "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0",
	},
	{
		inputLen:  1,
		hash:      "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
		keyedHash: "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c0490609413006fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c4e0cf7074885e92b0e3f125978b4154986d4fb202a3f331a3fb6cf349a3a70e49990f98fe4289761c8602c4e6ab1138d31d3b62218078b2f3ba9a88e1d08d0dd4cea11",
		deriveKey: "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c5827b91bf889b6b97c5477f535361caefca0b5d8c4746441c57617111933158950670f9aa8a05d791daae10ac683cbef8faf897c84e6114a59d2173c3f417023a35d6983f2c7dfa57e7fc559ad751dbfb9ffab39c2ef8c4aafebc9ae973a64f0c76551",
	},
	{
		inputLen:  1023,
		hash:      "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485",
		keyedHash: "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e890316d2e6d8b8c25b0a5b2180f94fb1a158ef508c3cde45e2966bd796a696d3e13efd86259d756387d9becf5c8bf1ce2192b87025152907b6d8cc33d17826d8b7b9bc97e38c3c85108ef09f013e01c229c20a83d9e8efac5b37470da28575fd755a10",
		deriveKey: "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea59c413264404661e9e4d955409dfe4ad3aa487871bcd454ed12abfe2c2b1eb7757588cf6cb18d2eccad49e018c0d0fec323bec82bf1644c6325717d13ea712e6840d3e6e730d35553f59eff5377a9c350bcc1556694b924b858f329c44ee64b884ef00d",
	},
	{
		inputLen:  1024,
		hash:      "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e",
		keyedHash: "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4f49c864acb7adafe2478e824afe51c8919d06168414c265f298a8094b1ad813a9b8614acabac321f24ce61c5a5346eb519520d38ecc43e89b5000236df0597243e4d2493fd626730e2ba17ac4d8824d09d1a4a8f57b8227778e2de",
		deriveKey: "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a6896843027066c23b601d3ddfb391e90d5c8eccdef4ae2a264bce9e612ba15e2bc9d654af1481b2e75dbabe615974f1070bba84d56853265a34330b4766f8e75edd1f4a1650476c10802f22b64bd3919d246ba20a17558bc51c199efdec67e80a227251808d8ce5bad",
	},
	{
		inputLen:  1025,
		hash:      "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a",
		keyedHash: "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930",
		deriveKey: "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f462118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8217cca46defa2751e7f3ad",
	},
	{
		inputLen:  2048,
		hash:      "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9",
		keyedHash: "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd10173b961cd574288194b23ece278c330fbb8585485e74967f31352a8183aa782b2b22f26cdcadb61eed1a5bc144b8198fbb0c13abbf8e3192c145d0a5c21633b0ef86054f42809df823389ee40811a5910dcbd1018af31c3b43aa55201ed4edaac74fe",
		deriveKey: "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23e2c11a1ebffcea4d80447867b61badb1383d842d4e79645d48dd82ccba290769caa7af8eaa1bd78a2a5e6e94fbdab78d9c7b74e894879f6a515257ccf6f95056f4e25390f24f6b35ffbb74b766202569b1d797f2d4bd9d17524c720107f985f4ddc583",
	},
	{
		inputLen:  2049,
		hash:      "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5448d519713e09413719431c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff63340285adec2aed3b51073ad3",
		keyedHash: "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e00b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d43b81447be22d5d8186f8f5919ba6bcc6846bd7d50726c06d245672c2ad4f61702c646499ee1173daa061ffe15bf45a631e2946d616a4c345822f1151284712f76b2b0e",
		deriveKey: "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf27316d8e9e79081a80b046b60f6a263616f33ca464bd78d79fa18200d06c7fc9bffd808cc4755277a7d5e09da0f29ed150f6537ea9bed946227ff184cc66a72a5f8c1e4bd8b04e81cf40fe6dc4427ad5678311a61f4ffc39d195589bdbc670f63ae70f4b6",
	},
	{
		inputLen:  3072,
		hash:      "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608335c09dc94ccf682f9951cdfc501bfe47b9c9189a6fc7b404d120258506341a6d802857322fbd20d3e5dae05b95c88793fa83db1cb08e7d8008d1599b6209d78336e24839724c191b2a52a80448306e0daa84a3fdb566661a37e11",
		keyedHash: "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df19177022f302d0529e4174cc507c463671217975e81dab02b8fdeb0d7ccc7568dd22574c783a76be215441b32e91b9a904be8ea81f7a0afd14bad8ee7c8efc305ace5d3dd61b996febe8da4f56ca0919359a7533216e2999fc87ff7d8f176fbecb3d6f34278b",
		deriveKey: "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b3604131bbd6e3ba573b6dd682fa0a63e5b165d39fc43a625d00207607a2bfeb65ff1d29292152e26b298868e3b87be95d6458f6f2ce6118437b632415abe6ad522874bcd79e4030a5e7bad2efa90a7a7c67e93f0a18fb28369d0a9329ab5c24134ccb0",
	},
	{
		inputLen:  3073,
		hash:      "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89da9bf25bc27139ae65a324918a5f9b7828181e52cf373c84f35b639b7fccbb985b6f2fa56aea0c18f531203497b8bbd3a07ceb5926f1cab74d14bd66486d9a91eba99059a98bd1cd25876b2af5a76c3e9eed554ed72ea952b603bf",
		keyedHash: "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a96d6da3fe985054d3478865be9a092250839a697bbda74e279e8a9e69f0025e4cfddd6cfb434b1cd9543aaf97c635d1b451a4386041e4bb100f5e45407cbbc24fa53ea2de3536ccb329e4eb9466ec37093a42cf62b82903c696a93a50b702c80f3c3c5",
		deriveKey: "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081576288e552647a9d86481c2cae75c2dd4e7c5195fb9ada1ef50e9c5098c249d743929191441301c69e1f48505a4305ec1778450ee48b8e69dc23a25960fe33070ea549119599760a8a2d28aeca06b8c5e9ba58bc19e11fe57b6ee98aa44b2a8e6b14a5",
	},
	{
		inputLen:  4096,
		hash:      "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe1623da896faf7e1114bebeadc1be30829b6f8af707d85c298f4f0ff4d9438aef948335612ae921e76d411c3a9111df62d27eaf871959ae0062b5492a0feb98ef3ed4af277f5395172dbe5c311918ea0074ce0036454f620",
		keyedHash: "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0bbb64a36edb564e01e4b4aaf3b060092a6b838bea44afebd2deb8298fa562b7b597c757b9df4c911c3ca462e2ac89e9a787357aaf74c3b56d5c07bc93ce899568a3eb17d9250c20f6c5f6c1e792ec9a2dcb715398d5a6ec6d5c54f586a00403a1af1de",
		deriveKey: "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9d78038f7b198596c6cc4a9ccf93223c08722d684f240ff6569075ed81591fd93f9fff1110b3a75bc67e426012e5588959cc5a4c192173a03c00731cf84544f65a2fb9378989f72e9694a6a394a8a30997c2e67f95a504e631cd2c5f55246024761b245",
	},
	{
		inputLen:  4097,
		hash:      "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c426bd26f619eab5d70af9a418b845c608840390f361630bd497b1ab44019316357c61dbe091ce72fc16dc340ac3d6e009e050b3adac4b5b2c92e722cffdc46501531956",
		keyedHash: "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc606db4976cfdd266ae0abf667d9481831ff12e0caa268e7d3e57260c0824115a54ce595ccc897786d9dcbf495599cfd90157186a46ec800a6763f1c59e36197e9939e900809f7077c102f888caaf864b253bc41eea812656d46742e4ea42769f89b83f",
		deriveKey: "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8a897f66a400fed9198fd61dd2d58d382458e64e100128075fc54b860934e8de2e84170734b06e1d212a117100820dbc48292d148afa50567b8b84b1ec336ae10d40c8c975a624996e12de31abbe135d9d159375739c333798a80c64ae895e51e22f3ad",
	},
	{
		inputLen:  5120,
		hash:      "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a2010ce8038c853e121e1544985133fccdd0a2d507e8e615e611e9a0ba4f47915f49e53d721816a9198e8b30f12d20ec3689989175f1bf7a300eee0d9321fad8da232ece6efb8e9fd81b42ad161f6b9550a069e66b11b40487a5f5059",
		keyedHash: "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e209b4dc9209cd80ce7c1f7c9a744658e7e288465717ae6e56d5463d4f80cdb2ef56495f6a4f5487f69749af0c34c2cdfa857f3056bf8d807336a14d7b89bf62bef2fb54f9af6a546f818dc1e98b9e07f8a5834da50fa28fb5874af91bf06020d1bf0120e",
		deriveKey: "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f6055d0cefd84d9d57fe792d65a278fd20384ac6c30fdb340092f1a74a92ace99c482b28f0fc0ef3b923e56ade20c6dba47e49227166251337d80a037e987ad3a7f728b5ab6dfafd6e2ab1bd583a95d9c895ba9c2422c24ea0f62961f0dca45cad47bfa0d",
	},
	{
		inputLen:  5121,
		hash:      "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff96adaab0613a6146cdaabe498c3a94e529d3fc1da2bd08edf54ed64d40dcd6777647eac51d8277d70219a9694334a68bc8f0f23e20b0ff70ada6f844542dfa32cd4204ca1846ef76d811cdb296f65e260227f477aa7aa008bac878f72257484f2b6c95",
		keyedHash: "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d0240d07e63f13667a8d1490e5e04f13eb617aea16a8c8a5aaed1ef6fbde1b0515e3c81050b361af6ead126032998290b563e3caddeaebfab592e155f2e161fb7cba939092133f23f9e65245e58ec23457b78a2e8a125588aad6e07d7f11a85b88d375b72d",
		deriveKey: "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c341a0add0ac032ab5aaea1e4e5b004707ec5681ae0fcbe3796974c0b1cf31a194740c14519273eedaabec832e8a784b6e7cfc2c5952677e6c3f2c3914454082d7eb1ce1766ac7d75a4d3001fc89544dd46b5147382240d689bbbaefc359fb6ae30263165",
	},
	{
		inputLen:  6144,
		hash:      "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca2054d742022da6fdda444ebc384b04a54c3ac5839b49da7d39f6d8a9db03deab32aade156c1c0311e9b3435cde0ddba0dce7b26a376cad121294b689193508dd63151603c6ddb866ad16c2ee41585d1633a2cea093bea714f4c5d6b903522045b20395c83",
		keyedHash: "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1dc35754060091dc5caf3efabe0603c60f45e415bb3407db67e6beb3d11cf8e4f7907561f05dace0c15807f4b5f389c841eb114d81a82c02a00b57206b1d11fa6e803486b048a5ce87105a686dee041207e095323dfe172df73deb8c9532066d88f9da7e",
		deriveKey: "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a1597099e3c6488aab6c48f3c15dbe1942d21dbcdc12115d19a8b8465fb54e9053323a9178e4275647f1a9927f6439e52b7031a0b465c861a3fc531527f7758b2b888cf2f20582e9e2c593709c0a44f9c6e0f8b963994882ea4168827823eef1f64169fef",
	},
	{
		inputLen:  6145,
		hash:      "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f18a2cfdd73c6e39dd75ce7c1c6e3ef238fd54465f053b25d21044ccb2093beb015015532b108313b5829c3621ce324b8e14229091b7c93f32db2e4e63126a377d2a63a3597997d4f1cba59309cb4af240ba70cebff9a23d5e3ff0cdae2cfd54e070022",
		keyedHash: "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539f3c184ca2f59780e27a576c1d1fb9772e99fd17881d02ac7dfd39675aca918453283ed8c3169085ef4a466b91c1649cc341dfdee60e32231fc34c9c4e0b9a2ba87ca8f372589c744c15fd6f985eec15e98136f25beeb4b13c4e43dc84abcc79cd4646c",
		deriveKey: "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5114493d029bdbd295aaa744a59e31f35c7f52dba9c3642f773dd0b4262a9980a2aef811697e1305d37ba9d8b6d850ef07fe41108993180cf779aeece363704c76483458603bbeeb693cffbbe5588d1f3535dcad888893e53d977424bb707201569a8d2",
	},
	{
		inputLen:  7168,
		hash:      "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a5707c321c83361793b9af62a40f43b523df1c8633cecb4cd14d00bdc79c78fca5165b863893f6d38b02ff7236c5a9a8ad2dba87d24c547cab046c29fc5bc1ed142e1de4763613bb162a5a538e6ef05ed05199d751f9eb58d332791b8d73fb74e4fce95",
		keyedHash: "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fca2f01d5277d69bb681c70fa8d36094f73ec06e452c80d2ff2257ed82e7ba348400989a65ee8daa7094ae0933e3d2210ac6395c4af24f91c2b590ef87d7788d7066ea3eaebca4c08a4f14b9a27644f99084c3543711b64a070b94f2c9d1d8a90d035d52",
		deriveKey: "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae223730d5a5175a38841693020669c7638f40b9bc1f9f39cf98bda7a5b54ae24218a800a2116b34665aa95d846d97ea988bfcb53dd9c055d588fa21ba78996776ea6c40bc428b53c62b5f3ccf200f647a5aae8067f0ea1976391fcc72af1945100e2a6dcb88",
	},
	{
		inputLen:  7169,
		hash:      "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e781798a8b20534be1ca9eb2ae2df3fae2ea60e48c6fb0b850b1385b5de0fe460dbe9d9f9b0d8db4435da75c601156df9d047f4ede008732eb17adc05d96180f8a73548522840779e6062d643b79478a6e8dbce68927f36ebf676ffa7d72d5f68f050b119c8",
		keyedHash: "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa5113c9e28d72fcbfc020814ce3f5d4fc867f01c8f5b6caf305b3ea8a8ba2da3ab69fabcb438f19ff11f5378ad4484d75c478de425fb8e6ee809b54eec9bdb184315dc856617c09f5340451bf42fd3270a7b0b6566169f242e533777604c118a6358250f54",
		deriveKey: "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d99b20652c016d88ba2a611bbd761668d5eda3e568e940faae24b0d9991c3bd25a65f770b89fdcadabcb3d1a9c1cb63e69721cacf1ae69fefdcef1e3ef41bc5312ccc17222199e47a26552c6adc460cf47a72319cb5039369d0060eaea59d6c65130f1dd",
	},
	{
		inputLen:  8192,
		hash:      "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a47778566b797a8c67df7b1d60b97b19288d2d877bb2df417ace009dcb0241ca1257d62712b6a4043b4ff33f690d849da91ea3bf711ed583cb7b7a7da2839ba71309bbf",
		keyedHash: "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a4834464159dcbc12a0ba0c6d6eb41bac0ed6585cabfe0aca36a375e6c5480c22afdc40785c170f5a6b8a1107dbee282318d00d915ac9ed1143ad40765ec120042ee121cd2baa36250c618adaf9e27260fda2f94dea8fb6f08c04f8f10c78292aa46102",
		deriveKey: "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d4c9e58958553513b67f84f8eac653aeeb02ae1d5672dcecf91cd9985a0e67f4501910ecba25555395427ccc7241d70dc21c190e2aadee875e5aae6bf1912837e53411dabf7a56cbf8e4fb780432b0d7fe6cec45024a0788cf5874616407757e9e6bef7",
	},
	{
		inputLen:  8193,
		hash:      "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3bb2282aa69be089359ea1154b9a9286c4a56af4de975a9aa4a5c497654914d279bea60bb6d2cf7225a2fa0ff5ef56bbe4b149f3ed15860f78b4e2ad04e158e375c1e0c0b551cd7dfc82f1b155c11b6b3ed51ec9edb30d133653bb5709d1dbd55f4e1ff6",
		keyedHash: "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5f03228648fd983aef045c2fa8290934b0866b615f585149587dda2299039965328835a2b18f1d63b7e300fc76ff260b571839fe44876a4eae66cbac8c67694411ed7e09df51068a22c6e67d6d3dd2cca8ff12e3275384006c80f4db68023f24eebba57",
		deriveKey: "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f12f20a01d6d622edf3de026a4db4e4526225debb93c1237934d71c7340bb5916158cbdafe9ac3225476b6ab57a12357db3abbad7a26c6e66290e44034fb08a20a8d0ec264f309994d2810c49cfba6989d7abb095897459f5425adb48aba07c5fb3c83c0",
	},
	{
		inputLen:  16384,
		hash:      "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d549073f2c660be0e81293767ed4e4929f9ad34bbb39a529334c57c4a381ffd2a6d4bfdbf1482651b172aa883cc13408fa67758a3e47503f93f87720a3177325f7823251b85275f64636a8f1d599c2e49722f42e93893",
		keyedHash: "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0df9e601b101e4cf63a404dfe50f2e1865bb12edc8fca166579ce0c70dba5a5c0fc960ad6f3772183416a00bd29d4c6e651ea7620bb100c9449858bf14e1ddc9ecd35725581ca5b9160de04060045993d972571c3e8f71e9d0496bfa744656861b169d65",
		deriveKey: "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e160dc0b1f09caa35f2f417b9ef309dfe5ebd67f4c9507995a531374d099cf8ae317542e885ec6f589378864d3ea98716b3bbb65ef4ab5e0ab5bb298a501f19a41ec19af84a5e6b428ecd813b1a47ed91c9657c3fba11c406bc316768b58f6802c9e9b57",
	},
	{
		inputLen:  31744,
		hash:      "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f",
		keyedHash: "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08b628be420b5e830fade7c080e351a076fbc38641ad80c736c8a18fe3c66ce12f95c61c2462a9770d60d0f77115bbcd3782b593016a4e728d4c06cee4505cb0c08a42ec",
		deriveKey: "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e9759adeb797a3fbf771b1bcea30150a020e317982bf0d6e7d14dd9f064bc11025c25f31e81bd78a921db0174f03dd481d30e93fd8e90f8b2fee209f849f2d2a52f31719a490fb0ba7aea1e09814ee912eba111a9fde9d5c274185f7bae8ba85d300a2b",
	},

	//
	// additional vectors that have not been verified with upstream.
	// they mainly exist to check that our results do not change for very large inputs.
	//

	{
		inputLen:  4 << 20, // 4 MB
		hash:      "4e94e6f582581a0f3855f3ce504b153e951e65036fe9e2f010b7e25473c54f9837d7b96d9b118cc52d9355b3a29569cbc089752c10081c47bd92e4395e5c02189d2231f218722a0d99790d9c9b69355b0fd9ff5837128a14e369dbadf3eb8e0e1d127c3bb7d3346f57c45962b863a1e9a75d5178abfb0cbcb6e43c352fcd32eba985d2",
		keyedHash: "182b531d06d2705f68e23dc6a5580481f3342ded15cece016b58e0922e75c0e337b279c31c1108cb768b12a56289d53bc20fb9397d25b2dd58a4489ad24edc9f3f7ba9ea8da9b2a13813d7d0126f612269ce8f44cab5afd623c1bdbfe1d28f03ad1dd2e7afd3fa7249fabb4466c83b86e3a231912a7c320985f7200544558f9a74d4bf",
		deriveKey: "14689cc67a8329afabf4ddfb9c5bd23b910ffcc69fb59beb934f867608f1005a55b9f2cb7c44d358a2bf9158b4d6b0cb3d114b1f681f25ba5ef2c8a92789d0c44374f2629905ed4ffcdbdf652e1bd745635adbb280e0ba5aa2c7501266ce0ad558ebf576aa5bfc1b45db879bf680fde43ae56dcbe06f993eafc8a5effec9180da943e1",
	},
}

var testText = `The Weaver of Whispers

The Weaver of Whispers, she sits in the wood,

Her loom made of shadows, her thread spun of mood.

She gathers the sighs of the wind in the trees.

And weaves them with tears shed on a salt-laden breeze.

Her fingers, like branches, are so gnarled and so thin,

They pluck at the heartstrings, let sorrow creep in.

She captures the laughter that rings through the air,

And blends it with silence, a tapestry rare.

The moon is her lantern, the stars her guide,

As she threads through the darkness, where secrets reside.

She listens to whispers on lips barely heard,

And weaves them with dreams, a fantastical word.

The patterns she creates, a kaleidoscope bright,

Reflecting the joys and the fears of the night.

A tapestry woven with love and with pain,

A story unfolded, again and again.

A traveler weary, with hope in his eyes,

He stumbles upon her, beneath moonlit skies.

He sees in her weaving, his life laid bare.

The triumphs and failures, the joys and despair.

He asks of the Weaver, Why show me this scene?

The tapestry woven of what might have been?

She smiles, a soft glimmer, a knowing so deep,

The past holds the lessons, the future to keep.

For every thread broken, a new one is spun,

The tapestry changes with each setting sun.

You hold in your hands the power to choose,

Which threads to unravel, which path to pursue?

The traveler ponders, his heart filled with awe,

At the wisdom she shares, and the mystical law.

He leaves with a lightness, a newfound belief,

That even in darkness, there's solace in grief.

The Weaver of Whispers, she sits in the wood,

Her loom made of shadows, her thread spun of mood.

She weaves through the ages, a timeless design,

A tapestry of life, forever entwined.`

var testKey = "MnltSkysWhispersWvngDstnysThread"

func TestRaw(t *testing.T) {
	check := func(t *testing.T, h *blake3_hasher, input []byte, hash string) {
		// write and finalize a bunch
		for i := range input {
			var tmp [32]byte
			_blake3_hasher_update(h, input[i:i+1])
			switch i % 8193 {
			case 0, 1, 2:
				_blake3_hasher_finalize(h, tmp[:])
			default:
			}
		}

		// check every output length requested
		for i := 0; i <= len(hash)/2; i++ {
			buf := make([]byte, i)
			_blake3_hasher_finalize(h, buf)
			if string(hash[:2*i]) != hex.EncodeToString(buf) {
				t.Errorf("hash mismatch: %x != %x", []byte(hash[:2*i]), []byte(hex.EncodeToString(buf)))
			}
		}
	}

	t.Run("Basic", func(t *testing.T) {
		for _, tv := range vectors {
			h := new(blake3_hasher)
			_blake3_hasher_init(h)
			check(t, h, tv.input(), tv.hash)

			// one more reset, full write, full read
			h = new(blake3_hasher)
			_blake3_hasher_init(h)
			_blake3_hasher_update(h, tv.input())
			buf := make([]byte, len(tv.hash)/2)
			_blake3_hasher_finalize(h, buf)
			if string(tv.hash) != hex.EncodeToString(buf) {
				t.Errorf("hash mismatch: %x != %x", tv.hash, hex.EncodeToString(buf))
			}
		}
	})

	t.Run("Keyed", func(t *testing.T) {
		for _, tv := range vectors {
			h := new(blake3_hasher)
			key := []byte(testVectorKey)
			_blake3_hasher_init_keyed(h, (*[32]byte)(key))
			check(t, h, tv.input(), tv.keyedHash)

			// one more reset, full write, full read
			h = new(blake3_hasher)
			_blake3_hasher_init_keyed(h, (*[32]byte)(key))
			_blake3_hasher_update(h, tv.input())
			buf := make([]byte, len(tv.keyedHash)/2)
			_blake3_hasher_finalize(h, buf)
			if string(tv.keyedHash) != hex.EncodeToString(buf) {
				t.Errorf("hash mismatch: %x != %x", tv.keyedHash, hex.EncodeToString(buf))
			}
		}
	})

	t.Run("DeriveKey", func(t *testing.T) {
		for _, tv := range vectors {
			h := new(blake3_hasher)
			_blake3_hasher_init_derive_key(h, []byte(testVectorContext))
			check(t, h, tv.input(), tv.deriveKey)
		}
	})
}

func TestHasher(t *testing.T) {
	check := func(t *testing.T, h *Hasher, input []byte, hash string) {
		// ensure reset works
		h.Write(input[:len(input)/2])
		h.Reset()

		// write and finalize a bunch
		for i := range input {
			var tmp [32]byte
			h.Write(input[i : i+1])
			switch i % 8193 {
			case 0, 1, 2:
				h.Sum(tmp[:0])
			default:
			}
		}

		// check every output length requested
		for i := 0; i <= len(hash)/2; i++ {
			buf := make([]byte, i)
			h.SumFill(buf)
			if string(hash[:2*i]) != hex.EncodeToString(buf) {
				t.Errorf("hash mismatch: %x != %x", []byte(hash[:2*i]), []byte(hex.EncodeToString(buf)))
			}
		}

		// one more reset, full write, full read
		h.Reset()
		h.Write(input)
		buf := make([]byte, len(hash)/2)
		h.SumFill(buf)
		if string(hash) != hex.EncodeToString(buf) {
			t.Errorf("hash mismatch: %x != %x", hash, hex.EncodeToString(buf))
		}
	}

	t.Run("Basic", func(t *testing.T) {
		for _, tv := range vectors {
			h := New()
			check(t, h, tv.input(), tv.hash)
		}
	})

	t.Run("Keyed", func(t *testing.T) {
		for _, tv := range vectors {
			key := []byte(testVectorKey)
			h := NewKeyed((*[32]byte)(key))
			check(t, h, tv.input(), tv.keyedHash)
		}
	})

	t.Run("DeriveKey", func(t *testing.T) {
		for _, tv := range vectors {
			h := NewDeriveKey([]byte(testVectorContext))
			check(t, h, tv.input(), tv.deriveKey)
		}
	})
}

func TestSum64(t *testing.T) {
	h := New()
	text := "Hello, World!"
	h.Write([]byte(text))

	sum := h.Sum64()
	if sum != uint64(15466241415402916392) {
		t.Errorf("sum mismatch: %x != %x", sum, uint64(15466241415402916392))
	}
}

func TestSum32(t *testing.T) {
	h := New()
	text := "Hello, World!"
	h.Write([]byte(text))

	sum := h.Sum32()
	if sum != uint32(2810612264) {
		t.Errorf("sum mismatch: %x != %x", sum, uint32(2810612264))
	}
}

func TestKeyed(t *testing.T) {
	h := NewKeyed((*[32]byte)([]byte(testKey)))
	h.Write([]byte(testText))
	if hex.EncodeToString(h.Sum(nil)) != "07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d" {
		t.Errorf("hash mismatch: %x != %x", h.Sum(nil), []byte("07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d"))
	}
}

func TestWriteString(t *testing.T) {
	h := NewKeyed((*[32]byte)([]byte(testKey)))
	h.WriteString(testText)
	if hex.EncodeToString(h.Sum(nil)) != "07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d" {
		t.Errorf("hash mismatch: %x != %x", h.Sum(nil), []byte("07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d"))
	}
}

func TestDestroy(t *testing.T) {
	h := NewKeyed((*[32]byte)([]byte(testKey)))
	h.Write([]byte(testText))
	if hex.EncodeToString(h.Sum(nil)) != "07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d" {
		t.Errorf("hash mismatch: %x != %x", h.Sum(nil), []byte("07439ab86d45364f7da3af713cfc3ce6f8c482414ca78913ed296811949e294d"))
	}

	h.Destroy()

	h.Write([]byte(testText))
	if hex.EncodeToString(h.Sum(nil)) != "b2fbef5a8ea9080eaaee55bbc930d797bab41d42abe20f34126c94f7c5aa03f6" {
		t.Errorf("hash mismatch: %x != %x", h.Sum(nil), []byte("b2fbef5a8ea9080eaaee55bbc930d797bab41d42abe20f34126c94f7c5aa03f6"))
	}
}

func TestSum256(t *testing.T) {
	h := Sum256([]byte(testText))
	if hex.EncodeToString(h[:]) != "b2fbef5a8ea9080eaaee55bbc930d797bab41d42abe20f34126c94f7c5aa03f6" {
		t.Errorf("hash mismatch: %x != %s", h, "b2fbef5a8ea9080eaaee55bbc930d797bab41d42abe20f34126c94f7c5aa03f6")
	}
}

func BenchmarkWrite1024(b *testing.B) {
	h := New()
	buffer := make([]byte, 1024)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}

func BenchmarkWrite512(b *testing.B) {
	h := New()
	buffer := make([]byte, 512)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}

func BenchmarkWrite256(b *testing.B) {
	h := New()
	buffer := make([]byte, 256)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}
func BenchmarkWrite128(b *testing.B) {
	h := New()
	buffer := make([]byte, 128)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}
func BenchmarkWrite64(b *testing.B) {
	h := New()
	buffer := make([]byte, 64)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}

func BenchmarkWrite32(b *testing.B) {
	h := New()
	buffer := make([]byte, 32)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}

func BenchmarkWrite16(b *testing.B) {
	h := New()
	buffer := make([]byte, 16)
	rand.Read(buffer)
	b.SetBytes(int64(len(buffer)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Write(buffer)
	}
}
