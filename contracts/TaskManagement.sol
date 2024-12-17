// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TaskManagement {
    struct DID {
        string identifier;
        address owner;
    }

    struct Task {
        uint id;
        string name;
        string description;
        uint priority;
        uint dueDate;
        address assignedTo;
        bool isCompleted;
        uint completedAt;
    }

    struct Credential {
        address issuer;
        string role;
        bytes32 hashed;
        uint256 issueAt;
    }

    uint public taskCounter = 0;
    mapping(address => DID) private dids;
    mapping (address => string) private roles;
    mapping(address => string[]) private roleHistory;
    mapping(address => Credential[]) private credentials;
    mapping(uint => Task) public tasks;

    event DIDCreated(address indexed owner, string identifier);
    event RoleAssigned(address indexed user, string role);
    event RoleIssued(address indexed issuer, address user, string role, bytes32 roleHash);
    event TaskCreated(address indexed assignee, uint taskID, string taskName);
    event TaskCompleted(address indexed assignee, uint taskID);

    // Ensures that the caller has the "manager" role.
    modifier onlyManager {
        require(keccak256(bytes(roles[msg.sender])) == keccak256(bytes("manager")), "Unauthorized action");
        _;
    }

    constructor() {
        roles[msg.sender] = "manager";
        roleHistory[msg.sender].push("manager");
    }

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
        credentials[_user].push(Credential(
            msg.sender,
            _role,
            roleHash,
            block.timestamp
        ));
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

    function getTasks() public view returns (Task[] memory) {
        require(dids[msg.sender].owner == address(0), "DID already exists for this address");

        Task[] memory userTasks = new Task[](taskCounter);
        uint index = 0;

        for (uint i = 0; i < taskCounter; i++) 
        {
            if (msg.sender == tasks[i].assignedTo) {
                userTasks[index] = tasks[i];
                index++;
            }
        }

        return userTasks;
    }

    function getTask(uint _id) public view returns (
        Task memory
    ) {
        require(dids[msg.sender].owner == address(0), "DID already exists for this address");

        Task storage task = tasks[_id];
        require(msg.sender == task.assignedTo, "Not authorized");

        return task;
    }

    function createTask(
        string memory _name,
        string memory _description,
        uint _priority,
        uint _dueDate,
        address _assignedTo
    ) onlyManager public {
        require(dids[msg.sender].owner == address(0), "DID already exists for this address");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        // Create new task for the assignee
        tasks[taskCounter] = Task(taskCounter, _name, _description, _priority, _dueDate, _assignedTo, false, 0);
        emit TaskCreated(_assignedTo, taskCounter, _name);

        // Increment the task amounts
        taskCounter++;
    }

    function completeTask(uint _taskId) public {
        require(dids[msg.sender].owner == address(0), "DID already exists for this address");

        // Fetch the task by it ID
        Task storage task = tasks[_taskId];
        require(msg.sender == task.assignedTo, "Not authorized");
        require(!task.isCompleted, "Task already completed");

        // Update the status of the task to completed
        task.isCompleted = true;
        task.completedAt = block.timestamp;

        emit TaskCompleted(task.assignedTo, task.id);
    }
}