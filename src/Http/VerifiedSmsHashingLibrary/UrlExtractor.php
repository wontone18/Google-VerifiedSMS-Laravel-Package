<?php
/*
Copyright 2019 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Contains regular expression pattern used to extract URLs.
 */
namespace Wontonee\Verifiedsms\Http\VerifiedSmsHashingLibrary;
 
class UrlExtractor {
	public $strictDomain = '(?:(?:(?:[a-z]+:)?\/\/)?|www\.)(?:\S+(?::\S*)?@)?(?:localhost|(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?:(?:[a-z\x{00a1}-\x{ffff}0-9}][-_]*)*[a-z\x{00a1}-\x{ffff}0-9]+)(?:\.(?:[a-z\x{00a1}-\x{ffff}0-9]-*)*[a-z\x{00a1}-\x{ffff}0-9]+)*(?:\.(?:travelersinsurance|northwesternmutual|vermögensberatung|vermögensberater|sandvikcoromant|kerryproperties|americanexpress|bananarepublic|americanfamily|cookingchannel|weatherchannel|kerrylogistics|cancerresearch|afamilycompany|spreadbetting|travelchannel|wolterskluwer|international|lifeinsurance|versicherung|lplfinancial|scholarships|construction|accountants|foodnetwork|kerryhotels|olayangroup|motorcycles|williamhill|bridgestone|barclaycard|photography|enterprises|engineering|சிங்கப்பூர்|playstation|calvinklein|investments|productions|progressive|redumbrella|rightathome|blackfriday|creditunion|blockbuster|contractors|lamborghini|healthcare|technology|onyourside|telefonica|management|industries|extraspace|eurovision|volkswagen|vlaanderen|basketball|nationwide|newholland|nextdirect|apartments|vistaprint|capitalone|accountant|properties|protection|prudential|university|realestate|swiftcover|immobilien|cuisinella|schaeffler|associates|tatamotors|creditcard|bnpparibas|mitsubishi|consulting|boehringer|republican|restaurant|foundation|homedepot|hisamitsu|firestone|financial|panasonic|stockholm|passagens|amsterdam|analytics|fairwinds|goodhands|kuokgroup|equipment|statefarm|statebank|barcelona|education|shangrila|travelers|ladbrokes|goldpoint|alfaromeo|vacations|lifestyle|pramerica|aquarelle|insurance|institute|scjohnson|allfinanz|marketing|accenture|marshalls|landrover|furniture|fujixerox|solutions|frontdoor|fresenius|yodobashi|melbourne|bloomberg|lancaster|microsoft|christmas|honeywell|community|directory|homesense|richardli|homegoods|feedback|cleaning|cityeats|saarland|commbank|cipriani|computer|chrysler|samsclub|reliance|السعودية|catholic|redstone|catering|uconnect|delivery|deloitte|democrat|diamonds|property|discount|discover|capetown|security|download|vanguard|plumbing|services|ventures|pictures|engineer|business|builders|shopping|ericsson|esurance|etisalat|budapest|everbank|exchange|brussels|pharmacy|verisign|broadway|bradesco|partners|clothing|fidelity|boutique|showtime|firmdale|training|football|clinique|observer|softbank|software|frontier|baseball|bargains|barefoot|barclays|goodyear|grainger|graphics|guardian|movistar|mortgage|hdfcbank|stcgroup|helsinki|holdings|supplies|hospital|attorney|merckmsd|memorial|mckinsey|maserati|marriott|infiniti|symantec|yokohama|ipiranga|istanbul|lundbeck|allstate|jpmorgan|airforce|telecity|lighting|woodside|abudhabi|company|farmers|fashion|schwarz|compare|cartier|ferrari|ferrero|panerai|reviews|dentist|origins|finance|science|organic|booking|كاثوليك|fishing|fitness|flights|shriram|florist|flowers|oldnavy|singles|chintai|digital|tiffany|forsale|trading|contact|lasalle|frogans|careers|پاکستان|fujitsu|இந்தியா|bestbuy|gallery|spiegel|bentley|genting|staples|starhub|neustar|network|netflix|netbank|bauhaus|caravan|اتصالات|capital|godaddy|cooking|banamex|samsung|domains|corsica|walmart|grocery|politie|country|statoil|guitars|coupons|hamburg|hangout|monster|courses|rentals|العليان|wanggou|storage|hitachi|католик|pioneer|holiday|yamaxun|avianca|watches|auspost|sandvik|audible|auction|shiksha|weather|hosting|hoteles|hotmail|channel|metlife|cricket|hyundai|citadel|athleta|cruises|website|bugatti|support|الجزائر|surgery|markets|college|toshiba|philips|schmidt|systems|youtube|cologne|android|iselect|ismaili|comcast|wedding|recipes|whoswho|موبايلي|jewelry|xfinity|exposed|juniper|alibaba|express|realtor|agakhan|lincoln|kitchen|limited|rexroth|temasek|komatsu|theater|liaison|leclerc|theatre|clubmed|tickets|windows|winners|lacaixa|academy|zuerich|brother|lancome|latrobe|abogado|lanxess|okinawa|भारतम्|center|tattoo|dating|datsun|racing|الاردن|quebec|viking|dealer|futbol|villas|unicom|nowruz|gallup|norton|degree|garden|virgin|nissay|nissan|vision|sanofi|zappos|george|chanel|travel|active|dental|tienda|alipay|giving|natura|design|global|nagoya|aramco|sydney|voting|chrome|direct|mutual|africa|museum|church|sakura|voyage|google|bostik|circle|gratis|vuelos|safety|امارات|walter|ファッション|boston|swatch|doctor|moscow|ryukyu|rogers|mormon|abbvie|مليسيا|rocher|monash|claims|health|suzuki|mobily|dunlop|mobile|hermes|tjmaxx|hiphop|dupont|durban|warman|онлайн|clinic|hockey|alsace|broker|alstom|pictet|agency|ارامكو|piaget|physio|emerck|energy|shouji|bayern|review|hotels|photos|abbott|xperia|москва|hughes|فلسطين|coffee|target|estate|webcam|beauty|yandex|mattel|taobao|imamat|events|berlin|supply|expert|abarth|select|taipei|comsec|condos|insure|market|camera|intuit|tkmaxx|bharti|family|makeup|maison|madrid|pfizer|viajes|secure|இலங்கை|luxury|jaguar|airbus|report|repair|author|xihuan|london|joburg|studio|coupon|locker|juegos|search|kaufen|social|living|otsuka|career|credit|soccer|kinder|kindle|stream|blanco|tennis|orange|cruise|kosher|schule|oracle|lefrak|flickr|caseih|school|ابوظبي|المغرب|online|reisen|casino|toyota|lawyer|anquan|lancia|olayan|airtel|realty|office|yachts|latino|lamer|tirol|lease|legal|lexus|works|koeln|world|lilly|linde|lipsy|xerox|lixil|loans|locus|lotte|lotto|jetzt|lupin|iveco|weibo|macys|irish|mango|intel|ikano|weber|বাংলা|media|hyatt|house|miami|horse|honda|homes|watch|money|mopar|guide|movie|gucci|group|gripe|wales|green|volvo|gmail|vodka|nadex|globo|glass|glade|gives|gifts|భారత్|nexus|vista|nikon|ninja|nokia|games|gallo|nowtv|forum|forex|omega|भारोत|संगठन|final|osaka|video|paris|fedex|parts|party|faith|phone|photo|epson|epost|email|edeka|ایران|earth|pizza|vegas|place|dubai|poker|drive|kyoto|dodge|praxi|press|prime|بازار|promo|delta|deals|quest|radio|dance|dabur|cymru|rehab|reise|بھارت|crown|codes|coach|سودان|همراه|cloud|ricoh|click|rocks|rodeo|ubank|rugby|tushu|citic|tunes|cisco|salon|cheap|chase|سورية|trust|cards|canon|sener|seven|ഭാരതം|sharp|shell|shoes|build|bosch|boats|嘉里大酒店|skype|sling|trade|smart|smile|black|bingo|solar|bible|space|sport|tours|stada|beats|baidu|azure|yahoo|store|autos|study|style|total|sucks|audio|swiss|toray|archi|apple|tools|amica|amfam|tatar|tokyo|today|aetna|tmall|zippo|adult|actor|tires|porn|fans|hsbc|fail|fage|erni|life|host|jprs|kred|mini|عمان|pics|mint|loft|ping|pink|jobs|work|dvag|сайт|hgtv|play|duns|duck|plus|wang|vana|pohl|mobi|here|help|post|doha|moda|hdfc|land|haus|prod|docs|prof|love|hair|dish|diet|desi|guru|dell|like|qpon|deal|moto|dclk|guge|raid|date|read|data|wiki|wien|cyou|jeep|بارت|ltda|weir|java|reit|goog|rent|ڀارت|coop|cool|voto|rest|golf|gold|gmbh|club|rich|vote|lego|luxe|rmit|عراق|kiwi|дети|city|room|limo|rsvp|itau|ruhr|name|xbox|ಭಾರತ|citi|safe|navy|شبكة|sale|vivo|viva|chat|maif|بيتك|组织机构|sapo|sarl|save|saxo|tube|cern|wine|cbre|cash|case|casa|cars|care|scor|scot|gift|ポイント|seat|ggee|camp|seek|call|news|cafe|next|sexy|تونس|グーグル|ଭାରତ|大众汽车|shaw|gent|shia|buzz|link|shop|ලංකා|ਭਾਰਤ|show|nico|book|bond|silk|sina|bofa|site|nike|lgbt|skin|info|blue|電訊盈科|gbiz|visa|クラウド|toys|sncf|blog|ভাৰত|immo|bing|bike|sohu|game|imdb|song|sony|ভারত|best|ભારત|spot|beer|town|fund|free|موقع|star|bbva|bank|band|live|baby|ford|food|भारत|ollo|auto|ieee|kpmg|flir|open|lidl|audi|asia|surf|asda|yoga|arte|arpa|army|fish|fire|kddi|arab|meet|film|香格里拉|talk|page|amex|ally|fido|akdn|taxi|fiat|meme|team|tech|aigo|zara|zero|pars|aero|teva|icbc|menu|loan|adac|tiaa|zone|fast|able|tips|pccw|farm|aarp|bcn|gdn|мон|man|gea|esq|pro|map|ing|ink|bnl|you|飞利浦|int|中文网|pru|mba|ups|uol|pub|uno|pwc|day|كوم|诺基亚|คอม|med|qvc|xyz|eus|dds|aco|мкд|men|aig|meo|car|red|ist|gle|セール|zip|itv|mil|bom|ren|iwc|mit|ads|boo|jcb|mlb|mls|jcp|mma|कॉम|afl|gmo|gmx|jio|ril|rio|rip|jlc|ubs|moe|moi|mom|jll|xin|jmp|jnj|tvs|abc|bar|run|bet|rwe|jot|joy|mov|fan|新加坡|goo|bot|com|dev|msd|dhl|mtn|mtr|sap|gop|got|sas|gov|ストア|tui|sbi|sbs|kfh|sca|scb|नेट|wtf|wtc|kia|nab|kim|орг|հայ|box|cat|trv|wow|nba|aaa|укр|nec|net|art|cba|cbn|ses|淡马锡|sew|sex|new|sfr|kpn|קום|krd|anz|diy|cbs|nfl|yun|ngo|nhk|ไทย|wme|dnp|бел|срб|ceb|bid|ceo|fit|hbo|aol|ком|ski|now|sky|dog|aeg|vip|vin|nra|nrw|ntt|lat|nyc|cfa|obi|dot|off|law|cfd|عرب|fly|lds|soy|dtv|vig|天主教|one|ong|onl|srl|srt|foo|hiv|ooo|aws|hkt|bio|org|win|stc|biz|قطر|app|ott|ovh|axa|dvr|buy|fox|crs|eat|xxx|frl|eco|bbc|pay|edu|hot|pet|vet|ftr|top|csc|bbt|llc|phd|tab|fun|how|қаз|みんな|abb|lol|我爱你|tax|bzh|fyi|tci|рус|tdk|pid|pin|lpl|tel|ibm|gal|ice|icu|ltd|cab|bcg|tjx|thd|cal|ifm|مصر|bms|gap|pnc|dad|wed|cam|bmw|hu|tj|tk|tg|tl|tm|tf|tn|to|td|tc|sz|sy|sx|sv|su|st|sr|so|sn|tr|sm|sl|sk|sj|si|sh|sg|se|sd|tt|sc|sb|sa|rw|tv|ru|tw|tz|ua|rs|ro|re|ug|uk|qa|py|pw|pt|ps|us|uy|uz|va|pr|pn|pm|vc|ve|pl|pk|ph|pg|pf|vg|vi|pe|pa|om|nz|nu|nr|np|no|nl|ni|ng|nf|ne|nc|na|vn|mz|my|mx|mw|mv|mu|mt|vu|ms|mr|mq|mp|mo|mn|mm|ml|mk|mh|mg|me|md|mc|ma|ly|lv|lu|wf|lt|ls|lr|lk|li|lc|lb|la|kz|ky|kw|kr|kp|kn|km|ws|ki|kh|kg|ke|jp|jo|jm|je|it|佛山|is|慈善|集团|在线|한국|ir|iq|点看|io|in|im|八卦|il|ie|公益|公司|id|网站|移动|th|ht|hr|hn|hm|hk|联通|gy|бг|gw|gu|时尚|微博|gt|gs|gr|gq|gp|삼성|gn|商标|商店|商城|gm|gl|ею|gi|新闻|工行|家電|gh|gg|中信|中国|中國|娱乐|谷歌|gf|ge|gd|购物|gb|ga|通販|fr|fo|fm|网店|fk|餐厅|网络|fj|fi|香港|eu|食品|et|台湾|台灣|手表|手机|es|er|eg|ee|ec|dz|do|dm|dk|dj|de|cz|cy|cx|cw|cv|cu|cr|co|cn|cm|cl|ck|澳門|닷컴|政府|ci|ch|cg|გე|机构|cf|健康|cd|cc|招聘|ca|рф|珠宝|bz|大拿|by|bw|ελ|世界|書籍|bv|bt|网址|닷넷|コム|bs|游戏|br|bo|企业|信息|bn|嘉里|bm|bj|广东|bi|bh|bg|bf|be|政务|bd|bb|ba|az|ax|aw|au|ye|at|as|ar|aq|ao|yt|am|za|al|ai|ag|af|ae|zm|ad|ac|zw))\.?)(?::\d{2,5})?(?:[\/?#][^\s"]*)?';

	public $relaxedDomain = "((?:\b|$|^)(?:(?:(?:http|https|rtsp):\/\/(?:(?:[a-zA-Z0-9\$\-\_\.\+\!\*\'\(\)\,\;\?\&\=]|(?:\%[a-fA-F0-9]{2})){1,64}(?:\:(?:[a-zA-Z0-9\$\-\_\.\+\!\*\'\(\)\,\;\?\&\=]|(?:\%[a-fA-F0-9]{2})){1,25})?\@)?)(?:(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9]){0,1}(?:\.(?=\S))?)+|((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))))?(?:\:\d{1,5})?)(?:[\/\?](?:(?:[a-zA-Z0-9;\/\?:@&=#~\-\.\+!\*'\(\),_\$])|(?:%[a-fA-F0-9]{2}))*)?(?:\b|$|^))";

	public $urlMatcher;

	public function __construct() {
		$this->urlMatcher = '/(' . $this->strictDomain . '|' . $this->relaxedDomain . ')/mui';
	}
}

?>