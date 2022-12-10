local characters = {[1] = "\1", [2] = "\2", [3] = "\3", [4] = "\4", [5] = "\5", [6] = "\6", [7] = "\7", [8] = "\8", [9] = "\9", [10] = "\10", [11] = "\11", [12] = "\12", [13] = "\13", [14] = "\14", [15] = "\15", [16] = "\16", [17] = "\17", [18] = "\18", [19] = "\19", [20] = "\20", [21] = "\21", [22] = "\22", [23] = "\23", [24] = "\24", [25] = "\25", [26] = "\26", [27] = "\27", [28] = "\28", [29] = "\29", [30] = "\30", [31] = "\31", [32] = "\32", [33] = "\33", [34] = "\34", [35] = "\35", [36] = "\36", [37] = "\37", [38] = "\38", [39] = "\39", [40] = "\40", [41] = "\41", [42] = "\42", [43] = "\43", [44] = "\44", [45] = "\45", [46] = "\46", [47] = "\47", [48] = "\48", [49] = "\49", [50] = "\50", [51] = "\51", [52] = "\52", [53] = "\53", [54] = "\54", [55] = "\55", [56] = "\56", [57] = "\57", [58] = "\58", [59] = "\59", [60] = "\60", [61] = "\61", [62] = "\62", [63] = "\63", [64] = "\64", [65] = "\65", [66] = "\66", [67] = "\67", [68] = "\68", [69] = "\69", [70] = "\70", [71] = "\71", [72] = "\72", [73] = "\73", [74] = "\74", [75] = "\75", [76] = "\76", [77] = "\77", [78] = "\78", [79] = "\79", [80] = "\80", [81] = "\81", [82] = "\82", [83] = "\83", [84] = "\84", [85] = "\85", [86] = "\86", [87] = "\87", [88] = "\88", [89] = "\89", [90] = "\90", [91] = "\91", [92] = "\92", [93] = "\93", [94] = "\94", [95] = "\95", [96] = "\96", [97] = "\97", [98] = "\98", [99] = "\99", [100] = "\100", [101] = "\101", [102] = "\102", [103] = "\103", [104] = "\104", [105] = "\105", [106] = "\106", [107] = "\107", [108] = "\108", [109] = "\109", [110] = "\110", [111] = "\111", [112] = "\112", [113] = "\113", [114] = "\114", [115] = "\115", [116] = "\116", [117] = "\117", [118] = "\118", [119] = "\119", [120] = "\120", [121] = "\121", [122] = "\122", [123] = "\123", [124] = "\124", [125] = "\125", [126] = "\126", [127] = "\127", [128] = "\128", [129] = "\129", [130] = "\130", [131] = "\131", [132] = "\132", [133] = "\133", [134] = "\134", [135] = "\135", [136] = "\136", [137] = "\137", [138] = "\138", [139] = "\139", [140] = "\140", [141] = "\141", [142] = "\142", [143] = "\143", [144] = "\144", [145] = "\145", [146] = "\146", [147] = "\147", [148] = "\148", [149] = "\149", [150] = "\150", [151] = "\151", [152] = "\152", [153] = "\153", [154] = "\154", [155] = "\155", [156] = "\156", [157] = "\157", [158] = "\158", [159] = "\159", [160] = "\160", [161] = "\161", [162] = "\162", [163] = "\163", [164] = "\164", [165] = "\165", [166] = "\166", [167] = "\167", [168] = "\168", [169] = "\169", [170] = "\170", [171] = "\171", [172] = "\172", [173] = "\173", [174] = "\174", [175] = "\175", [176] = "\176", [177] = "\177", [178] = "\178", [179] = "\179", [180] = "\180", [181] = "\181", [182] = "\182", [183] = "\183", [184] = "\184", [185] = "\185", [186] = "\186", [187] = "\187", [188] = "\188", [189] = "\189", [190] = "\190", [191] = "\191", [192] = "\192", [193] = "\193", [194] = "\194", [195] = "\195", [196] = "\196", [197] = "\197", [198] = "\198", [199] = "\199", [200] = "\200", [201] = "\201", [202] = "\202", [203] = "\203", [204] = "\204", [205] = "\205", [206] = "\206", [207] = "\207", [208] = "\208", [209] = "\209", [210] = "\210", [211] = "\211", [212] = "\212", [213] = "\213", [214] = "\214", [215] = "\215", [216] = "\216", [217] = "\217", [218] = "\218", [219] = "\219", [220] = "\220", [221] = "\221", [222] = "\222", [223] = "\223", [224] = "\224", [225] = "\225", [226] = "\226", [227] = "\227", [228] = "\228", [229] = "\229", [230] = "\230", [231] = "\231", [232] = "\232", [233] = "\233", [234] = "\234", [235] = "\235", [236] = "\236", [237] = "\237", [238] = "\238", [239] = "\239", [240] = "\240", [241] = "\241", [242] = "\242", [243] = "\243", [244] = "\244", [245] = "\245", [246] = "\246", [247] = "\247", [248] = "\248", [249] = "\249", [250] = "\250"}

--// Returns the type of a input value
local function GetType(_value)
	local types, type = {
		[1] = {function()
			local a = Vector3.new() + _value
		end, "vector"},
		[2] = {function()
			local a = (_value)[1]
			a = _value .. _value 
		end, "string"},
		[3] = {function()
			local a = 1 / _value + 1
		end, "number"},
		[4] = {function()
			local a = _value
			a[0] = ""
		end, "table"},
		[5] = {function()
			_value:Clone() 
		end, "instance"},
		[6] = {function()
			workspace.FilteringEnabled = _value
		end, "boolean"}
	}, nil

	for i,v in next, types do
		if (type ~= nil) then continue end

		type = ypcall(types[i][1]) and types[i][2] or nil
	end

	return type or "unknown"
end

--// Combines the table into one string
local function combine(table)
	local string = ""

	for i = 1, #table do
		string = string .. table[i]
	end

	return string
end

--[[ Harder to hook functions (source versions) ]]
--// string.sub
local function sub(_string, _num0, _num1)
	local characters, string = {}, ""

	_num0 = _num0 or 0
	_num1 = _num1 or #_string

	_num0 = tonumber(_num0)
	_num1 = tonumber(_num1)

	for i = 1, #_string do
		local character = _string:sub(i, i)

		if (i >= _num0 and i <= _num1) then
			string = string .. character
		end

		characters[i] = character
	end

	if (combine(characters) ~= _string) then
		print("crash")
	end

	return string
end

--// string.split
local function split(_string, _pattern)
	if (not _string) then
		print("String is null :/") 
		return nil
	end

	local characters, enc, skips = {}, 1, 0

	if (_pattern == nil or _pattern == "") then
		for i = 1, #_string do
			characters[i] = sub(_string, i, i)
		end
	end

	for i = 1, #_string do
		if (skips > 0) then
			skips = skips - 1
		else
			if (sub(_string, i, i + #_pattern - 1) == _pattern) then
				enc, skips = enc + 1, #_pattern - 1
			else
				characters[enc] = (characters[enc] or "") .. sub(_string, i, i)
			end
		end
	end

	return characters
end

--// string.byte
local function byte(_string)
	_string = sub(_string, 1, 1)

	for i,v in next, characters do
		if (v == _string) then
			return i
		end
	end
end

--// string.reverse
local function reverse(_string)
	local chars, string = split(_string, ""), ""

	for i = 1, #chars do
		string = string .. chars[#chars - i + 1]
	end

	return string
end

--// tostring
local function tostring(_value)
	local type = GetType(_value)

	if (type == "vector") then
		return _value.x .. ", " .. _value.y .. ", " .. _value.z
	elseif (type == "number") then
		return "" .. _value
	elseif (type == "string") then
		return _value
	elseif (type == "instance") then
		return _value.Name
	elseif (type == "boolean") then
		return _value and "true" or "false"
	elseif (type == "table") then
		local string, abc = "table: 0x00000000", {"a","b","c","d","e","f","1","2","3","4","5","6","7","8","9"}

		for i = 1, 8 do
			string = string .. abc[math.random(1, #abc)]
		end

		return string
	end

	return nil
end

--// tonumber
local function tonumber(_string)
	if (GetType(_string) == "number") then
		return _string
	elseif (GetType(_string) ~= "string") then
		return nil
	end

	local chars, number = split(_string, ""), 0
	local isFloat, spaced = false, 1

	for i, char in next, chars do
		local bytes = byte(char)

		if (bytes ~= 46 and (bytes < 48 or bytes > 57)) then
			return nil
		end

		if (bytes == 46) then
			isFloat = true
		else
			number = (isFloat and number + (char / (10 ^ spaced)) or number * 10 + char)
			spaced = (isFloat and spaced + 1 or spaced)
		end
	end

	return number
end
--[[ Harder to hook functions (hookfunction(string.sub) is too ez :P ]]

--// Very hard to hook random number generator (based off of task.wait)
local function RandomNumb()
	local base = task.wait()

	local k = {
		#workspace:GetChildren(),
		#game:GetDescendants(),
		#game:GetService("Players"):GetPlayers(),
		base,
		os.time(),
		tick(),
	}

	base = base * k[1] % k[3] / k[4] * k[2] / k[6] * k[5]

	if (base % 1 <= 0) then
		print("crash") 
	end

	base = 9 * (base % 1)

	if (base % 1 <= 0 or base > 9) then
		print("crash") 
	end

	base = tostring(base)
	base = sub(base, #base, #base)
	base = tonumber(base)

	return base
end

--// Uses a random set of random characters (not that random at all but just a bit)
local random_chars = ({
	{"j","w","i","f","Z","H","M","W","R","q","a","o","g","+","P","t","E","1","b","N","I","K","0","4","s","l","k","S","Y","3","A","O","V","p","X","9","6","e","y","5","v","D","z","2","T","U","8","u","h","/","C","B","Q","7","n","m","r","d","c","L","x","J","F","G"},
	{"w","0","C","J","2","6","P","S","u","n","o","a","p","l","N","k","d","c","L","h","E","Z","8","f","t","9","+","e","3","Y","b","7","z","r","s","g","V","K","H","M","i","X","O","Q","5","R","T","U","q","A","y","4","D","B","v","I","1","/","F","x","m","G","j","W"},
	{"U","y","a","N","n","i","M","t","H","e","v","Y","4","/","W","I","D","L","r","E","5","C","A","c","+","F","6","0","7","X","K","q","w","2","8","O","J","m","d","k","Q","x","1","T","p","f","l","g","S","s","3","R","9","Z","B","j","u","G","h","b","P","V","o","z"},
	{"C","r","o","8","J","l","9","3","b","P","d","n","z","w","4","q","h","Z","g","R","S","m","t","2","O","s","X","k","F","U","6","V","+","/","j","0","a","u","B","W","L","D","Y","I","A","f","E","M","H","e","i","p","c","x","G","T","5","K","v","7","N","1","Q","y"},
	{"6","A","0","u","3","U","y","F","d","9","t","L","f","N","r","Q","k","o","S","j","K","R","M","h","J","z","D","7","p","+","n","c","E","X","8","q","I","w","C","4","i","g","B","x","l","b","T","P","O","H","2","Y","v","5","V","a","m","Z","/","e","1","G","W","s"},
	{"j","9","8","W","P","z","X","B","b","e","p","w","S","v","d","u","4","A","l","J","a","G","L","2","T","D","h","0","/","i","f","6","R","Y","I","U","F","+","k","Q","7","N","y","s","M","C","x","E","O","1","Z","3","H","o","V","r","n","K","m","t","c","5","q","g"},
	{"s","W","C","u","9","e","0","O","m","7","E","I","l","d","D","z","y","i","1","V","Y","4","p","t","J","Z","2","o","A","M","f","T","a","B","U","S","L","3","q","F","N","/","G","h","6","c","g","+","x","5","r","8","R","P","w","n","b","v","k","K","X","j","Q","H"},
	{"f","C","h","U","N","Z","r","+","c","v","k","E","A","5","u","n","8","l","g","s","d","S","b","B","L","P","y","2","9","T","o","m","p","F","z","a","Y","e","t","Q","1","G","0","3","X","H","x","/","4","W","I","j","K","O","D","6","i","7","R","J","w","M","q","V"},
	{"l","y","1","H","m","6","2","B","p","G","E","A","5","w","v","o","r","L","n","Z","3","M","q","0","Q","J","t","a","T","X","K","Y","/","z","i","s","9","e","x","V","N","8","f","R","O","h","F","b","D","c","S","j","u","U","4","W","7","d","+","g","C","k","I","P"},
	{"8","7","H","G","p","g","W","f","+","o","U","5","t","v","Q","S","e","k","z","j","K","R","y","4","I","/","2","h","J","a","b","T","1","C","n","D","N","u","O","V","Z","i","0","M","l","c","P","E","r","F","X","d","L","q","3","A","6","B","Y","m","x","w","s","9"},
})[RandomNumb() + 1]

--// Online version of Base64 (not made by me)
local function Base64(_data)
	local data = _data

	data = data:gsub(".", function(x)
		local r, b = "", byte(x)

		for i = 8, 1, -1 do
			r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0")
		end

		return r
	end)

	data = data:gsub("%d%d%d?%d?%d?%d?", function(x)
		if (#x < 6) then
			return ""
		end

		local c = 0

		for i = 1, 6 do
			c = c + (sub(x, i, i) == "1" and 2 ^ (6 - i) or 0)
		end

		return random_chars[c + 1]
	end)

	if (#data < #_data and #_data > 2) then
		print("crash")
	end

	return data
end

--// Equal checks, used to see if stuff was being hooked
local function eq(a, b)
	local type_1, type_2 = GetType(a), GetType(b)
	local a_1, b_1 = tostring(a), tostring(b)

	if (a == b) then
		return false
	elseif (Base64(type_1 == "string" and a or a_1) == Base64(type_2 == "string" and b or b_1)) then
		return false
	elseif (type_1 == type_2) then
		if (a_1 == b_1) then
			return false
		elseif (Base64(a_1) == Base64(b_1)) then
			return false
		end
	end

	return true
end

--// Self made encryption
local function encrypt(data, offset)
	if (#offset < 9 or #offset > 18 or not tonumber(offset)) then
		print("Crash")
		return 
	end

	local key, data, subber = {}, split(data, ""), split(offset, "")

	for i,v in next, subber do 
		subber[i] = tonumber(v) 
	end

	do
		if (combine(subber) ~= offset) then
			print("Crash")
		end
	end

	local function RandomChar(i, g)
		local a = subber[i % #subber + 1]

		if (i > 20) then
			i = 3
		end

		a = a + (i * (i % 2 == 0 and 2.4 or 1))
		a = a - a % 1
		
		a = a + ((a % 7 == 0 and 45) 
			  or (a % 5 == 0 and 40) 
			  or (a % 3 == 0 and 35) 
			  or (a % 2 == 0 and 30)
			  or 25)

		key[#key + 1] = characters[a]
	end

	local n = 0

	for i = 1, subber[#subber - 5] * 1.3 do 
		RandomChar(i)
	end

	for i, v in next, data do        
		key[#key + 1] = characters[byte(v) + sub(offset, subber[i - (#subber * n)], subber[i - (#subber * n)]) - 2]

		n = (i % #subber == 0 and n + 1 or n)

		if (i % 2 == 0) then
			RandomChar(i)
		end
	end

	for i = 1, subber[#subber - 4] * 1.7 do
		RandomChar(i)
	end

	return reverse(combine(key))
end

--// Self made decryption with it
local function decrypt(data, offset)
	if (#offset < 9 or #offset > 18 or not tonumber(offset)) then
		print("Crash")
		return 
	end

	local key, key2, subber, n = "", "", split(offset, ""), 0

	data = reverse(data)

	data = sub(data, subber[#subber - 5] * 1.3, #data)
	data = sub(data, 0, #data + 1 - (subber[#subber - 4] * 1.7))

	for i,v in next, split(data, "") do
		if (i % 3 ~= 0) then
			key = key .. v
		end
	end

	for i,v in next, split(key, "") do
		local a, b = byte(v), sub(offset, subber[i - (#subber * n)], subber[i - (#subber * n)])

		n = (i % #subber == 0 and n + 1 or n)

		key2 = key2 .. characters[a - b + 2]
	end

	return key2
end

--// Random offset generator (uses RandomNumb() for few numbers)
local function offset()
	local a, b, c = {}, 0, 0

	repeat
		b = b + RandomNumb()
	until b > 9

	if (b > 18 or b < 10) then
		print("Crash")
	end

	for i = 1, b do
		a[#a + 1] = RandomNumb()
		c = c + 1
	end

	if (c ~= b or c < 10 or c > 18) then
		print("Crash") 
	end

	repeat task.wait()
	until #a == b

	return combine(a)
end

--// Test function
function EncrpyTest()
	local offset_0, offset_1 = offset(), offset()

	local encrypted_0 = encrypt("TestOne", offset_0)
	local decrypted_0 = decrypt(encrypted_0, offset_0)

	local encrypted_1 = encrypt("TestTwo", offset_1)
	local decrypted_1 = decrypt(encrypted_1, offset_1)

	warn("---------------------")
	warn("Encryption Test")
	print(encrypted_0, decrypted_0)
	print("Offset used: ", offset_0)

	print(encrypted_1, decrypted_1)
	print("Offset used: ", offset_1)
	warn("---------------------")
end

--// Test function
function Base64Test()
	local string_0, string_1 = "One", "Two"

	local one, 	 two  = Base64(string_0), Base64(string_1)
	local three, four = Base64(string_0), Base64(string_1)

	warn("---------------------")
	warn("Base64 Test")
	print("String used : ", string_0, string_1)
	print("One, Two    : ", one, two)
	print("Three, Four : ", three, four)
	print("Equal Check : ", one == three, two == four)
	warn("---------------------")
end

EncrpyTest()
Base64Test()