// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Kong Phirom
// Hul Sambath
// Prak Pichey
// Him Ronald
// Chhim Kakada

contract DIDRegistry {
    // Contract will store and manage DIDs
    struct DID {
        string identifier;
        address owner;
    }

    struct Metadata {
        string name;
        string email;
        string profilePicture;
    }

    struct Credential {
        address issuer;
        string role;
        bytes32 hashed;
        uint256 issueAt;
    }

    // Link each Ethereum address to a struct
    mapping(address => DID) private dids;
    mapping (address => string) private roles;
    mapping(address => string[]) private roleHistory;
    mapping(address => Metadata) private metadata;
    mapping(address => Credential) private credentials;

    modifier onlyManager {
        // Verify that the issuer has manager role
        require(keccak256(bytes(roles[msg.sender])) == keccak256(bytes("manager")), "Unauthorized action");
        _;
    }

    constructor() {
        roles[msg.sender] = "manager";
        roleHistory[msg.sender].push("manager");
    }

    // event DIDCreated: Define an event
    // address indexed owner: Logs the user's address (indexed for easy search)
    // string identifier: Logs the created DID
    event DIDCreated(address indexed owner, string identifier);
    event MetadataCreated(address indexed  owner, string name, string email, string profilePicture);
    event RoleAssigned(address indexed user, string role);
    event RoleIssued(address indexed issuer, address user, string role, bytes32 roleHash);

    function createDID(string memory _identifier) public {
        require(bytes(_identifier).length > 0, "Identifier cannot be empty");
        require(dids[msg.sender].owner == address(0), "DID already exists for this address");

        dids[msg.sender] = DID(_identifier, msg.sender);

        emit DIDCreated(msg.sender, _identifier);
    }

    function getDID() public view returns (string memory) {
        require(dids[msg.sender].owner != address(0), "No DID found for this address");
        return dids[msg.sender].identifier;
    }

    function updateDID(string memory _newIdentifier) public {
        require(bytes(_newIdentifier).length > 0, "New identifier cannot be empty");
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        
        // Verify that the old identifier matches the existing one
        string memory oldIdentifier = getDID();
        require(keccak256(bytes(oldIdentifier)) != keccak256(bytes(_newIdentifier)), "Invalid new identifier");
        
        // Update the DID with the new identifier
        dids[msg.sender].identifier = _newIdentifier;
        
        // Emit an event for the DID update
        emit DIDCreated(msg.sender, _newIdentifier);
    }

    function setMetadata(
        string memory _name, 
        string memory _email, 
        string memory _profilePicture
    ) public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_email).length > 0, "Email cannot be empty"); // email is important for $reason$

        metadata[msg.sender] = Metadata(
            _name,
            _email,
            _profilePicture
        );

        emit MetadataCreated(msg.sender, _name, _email, _profilePicture);
    }

    function getMetadata() public view returns (Metadata memory) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        return metadata[msg.sender];
    }

    function assignRole(address _user, string memory _role) onlyManager public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_role).length > 0, "Role cannot be empty");

        roles[_user] = _role;
        roleHistory[_user].push(_role);

        emit RoleAssigned(_user, _role);
    }

    function issueRole(address _user, string memory _role) onlyManager public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_role).length > 0, "Role cannot be empty");

        bytes32 roleHash = keccak256(abi.encodePacked(msg.sender, _user, _role, block.timestamp));

        credentials[_user] = Credential(
            msg.sender,
            _role,
            roleHash,
            block.timestamp
        );
        roleHistory[_user].push(_role);

        emit RoleIssued(msg.sender, _user, _role, roleHash);
    }

    function getRole() public view returns (string[] memory) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");

        //get userdid to find in array.
        string[] memory userRoles = roleHistory[msg.sender];

        //if you got 0, it mean u dont have role yet
        //if you didn't get 0, return that array. 
        require(userRoles.length > 0, "No roles assigned for this user");

        return userRoles;
    }
}