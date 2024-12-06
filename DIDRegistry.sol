// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DIDRegistry
 * @dev Contract to store and manage DIDs
 * 
 * Authors:
 * - Kong Phirom
 * - Hul Sambath
 * - Prak Pichey
 * - Him Ronald
 * - Chhim Kakada
 */

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

    // Ensures that the caller has the "manager" role.
    modifier onlyManager {
        require(keccak256(bytes(roles[msg.sender])) == keccak256(bytes("manager")), "Unauthorized action");
        _;
    }

    constructor() {
        roles[msg.sender] = "manager";
        roleHistory[msg.sender].push("manager");
    }

    /* 
    * event DIDCreated: Define an event
    * address indexed owner: Logs the user's address (indexed for easy search)
    * string identifier: Logs the created DID
    */
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
        // email cannot be empty because it is use to link between the decentralized world and traditional systems
        require(bytes(_email).length > 0, "Email cannot be empty");

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

    // Allow a manager to assign role to a user
    function assignRole(address _user, string memory _role) onlyManager public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_role).length > 0, "Role cannot be empty");

        roles[_user] = _role;
        roleHistory[_user].push(_role);

        emit RoleAssigned(_user, _role); // RoleAssigned event is emitted to log the assignment.
    }

    // Similar to assignRole, It performs the same checks for an existing DID and non-empty role. This is used for verify user's role.
    function issueRole(address _user, string memory _role) onlyManager public {
        // checks for an existing DID and non-empty role.
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_role).length > 0, "Role cannot be empty");

        // generates a unique roleHash
        bytes32 roleHash = keccak256(abi.encodePacked(msg.sender, _user, _role, block.timestamp));

        // store the new Credential in the Credentials[_user] mapping for the user
        credentials[_user] = Credential(
            msg.sender,
            _role,
            roleHash,
            block.timestamp
        );
        roleHistory[_user].push(_role);

        emit RoleIssued(msg.sender, _user, _role, roleHash); // RoleIssued event is emitted to log the issuance at here
    }

    // This function allows a user to retrieve their assigned roles. If the user has no roles assigned, it throws an error.
    function getRole() public view returns (string[] memory) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");

        // Get user roles array
        string[] memory userRoles = roleHistory[msg.sender];

        // if you got 0, it mean you don't have any role yet
        require(userRoles.length > 0, "No roles assigned for this user");

        // if you didn't get 0, return that array. 
        return userRoles;
    }
}