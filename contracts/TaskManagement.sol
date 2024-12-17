// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TaskManagement
 * @dev Contract to create and manage Tasks
 * 
 * Authors:
 * - Kong Phirom
 * - Hul Sambath
 * - Prak Pichey
 * - Him Ronald
 * - Chhim Kakada
 */
contract TaskManagement {
    struct DID {
        string identifier;
        address owner;
    }

    enum Priority { Low, Meduim, High }
    struct Task {
        uint id;
        string title;
        string description;
        Priority priority;
        uint dueDate;
        address assignedTo;
        bool isCompleted;
        uint completedAt;
    }

    struct Credential {
        address issuer;
        string role;
        bytes32 roleHash;
        uint256 issueAt;
    }

    mapping(address => DID) private dids;
    mapping (address => string) private roles;
    mapping(address => string[]) private roleHistory;
    mapping(address => Credential[]) private credentials;
    
    uint private taskCounter = 0;
    mapping(uint => Task) private tasks;    // All tasks for manager to keep track of
    mapping(address => uint[]) private userTasks;   // Specific user tasks

    event DIDCreated(address indexed owner, string identifier);
    event RoleAssigned(address indexed user, string role);
    event RoleIssued(address indexed issuer, address user, string role, bytes32 roleHash);
    event RoleVerified(address indexed issuer, string role, bool status);

    event TaskCreated(address indexed issuer, address assignee, uint id);
    event TaskReassigned(address indexed issuer, address newAssignee, uint id);
    event TaskCompleted(address indexed assignee, uint id);
    event TaskOwnershipVerified(uint indexed id, address assignee, bool isOwner);
    event TaskStatusVerified(uint indexed id, bool isComplete);
    event TaskDueDateVerified(uint indexed id, bool isValid);

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
        roles[_user] = _role;
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

    // Verify user role
    function verifyRole(address _user, address _issuer, string memory _role) public returns (bool) {
        require(dids[_user].owner != address(0), "No existing DID found for this user");
        require(credentials[_user].length > 0, "User does not have any credential");

        // Grab latest user credential
        Credential memory latestCredential = credentials[_user][credentials[_user].length - 1];

        // Grab the stored hash from credential
        bytes32 storedRoleHash = latestCredential.roleHash;

        // Hash the role with user inputs
        bytes32 roleHash = keccak256(abi.encodePacked(_issuer, _user, _role, latestCredential.issueAt));

        bool status = storedRoleHash == roleHash;
        emit RoleVerified(_issuer, _role, status);
        return status;
    }

    function createTask(
        string memory _title,
        string memory _description,
        Priority _priority,
        uint _dueDate,
        address _assignedTo
    ) onlyManager public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(bytes(_title).length > 0, "Title cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(_priority <= Priority.High, "Priority out of range (Low: 0, Medium: 1, High: 2)");
        require(_dueDate > block.timestamp, "Due date must be in the future");

        // Create new task for the assignee
        tasks[taskCounter] = Task(taskCounter, _title, _description, _priority, _dueDate, _assignedTo, false, 0);
        userTasks[_assignedTo].push(taskCounter);   // Add task ID to user tasks
        emit TaskCreated(msg.sender, _assignedTo, taskCounter);

        // Increment the task amounts
        taskCounter++;
    }

    // Reassigning the task when needed (only done by manager)
    function reassignTask(uint _id, address _newAssignee) onlyManager public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(tasks[_id].assignedTo != _newAssignee, "This task already belonged to the user");

        address oldAssignee = tasks[_id].assignedTo;

        // Reassigned the task
        tasks[_id].assignedTo = _newAssignee;

        // Remove the task from previous assignee tasks
        uint[] storage previousTasks = userTasks[oldAssignee];
        for (uint i = 0; i < previousTasks.length; i++) {
            if (previousTasks[i] == _id) {
                // Swap the task to last position and pop it off
                previousTasks[i] = previousTasks[previousTasks.length - 1];
                previousTasks.pop();
                break;
            }
        }

        // Add the task to new assignee tasks
        userTasks[_newAssignee].push(_id);
        
        emit TaskReassigned(msg.sender, _newAssignee, _id);
    }

    // Fetch all tasks in the system
    function getTasks() onlyManager public view returns (Task[] memory) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(taskCounter > 0, "No tasks have been assigned");

        Task[] memory tasksArray = new Task[](taskCounter);
        for (uint i = 0; i < taskCounter; i++) 
        {
            tasksArray[i] = tasks[i];
        }

        return tasksArray;
    }

    // Fetch all specific user tasks
    function getUserTasks() public view returns (Task[] memory) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");

        uint[] memory taskIds = userTasks[msg.sender];
        require(taskIds.length > 0, "You have no tasks");

        Task[] memory userTasksArray = new Task[](taskIds.length);
        for (uint i = 0; i < taskIds.length; i++) {
            userTasksArray[i] = tasks[taskIds[i]];
        }

        return userTasksArray;
    }

    function getTask(uint _id) public view returns (
        Task memory
    ) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(tasks[_id].assignedTo != address(0), "Task not found");
        require(msg.sender == tasks[_id].assignedTo || 
                keccak256(bytes(roles[msg.sender])) == keccak256(bytes("manager")), "Not authorized");

        return tasks[_id];
    }

    function completeTask(uint _id) public {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(msg.sender == tasks[_id].assignedTo, "Not authorized");
        require(!tasks[_id].isCompleted, "Task already completed");

        // Update the status of the task to completed
        tasks[_id].isCompleted = true;
        tasks[_id].completedAt = block.timestamp;

        emit TaskCompleted(tasks[_id].assignedTo, _id);
    }

    function verifyTaskOwnership(uint _id, address _assignee) public returns (bool) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(tasks[_id].assignedTo != address(0), "Task not found");

        bool isOwner = tasks[_id].assignedTo == _assignee;

        emit TaskOwnershipVerified(_id, _assignee, isOwner);
        return isOwner;
    }

    function verifyTaskStatus(uint _id) public returns (bool) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(tasks[_id].assignedTo != address(0), "Task not found");

        bool isCompleted = tasks[_id].isCompleted;

        emit TaskStatusVerified(_id, isCompleted);
        return isCompleted;
    }

    function verifyTaskDueDate(uint _id) public returns (bool) {
        require(dids[msg.sender].owner != address(0), "No existing DID found for this address");
        require(tasks[_id].assignedTo != address(0), "Task not found");

        bool isValid = tasks[_id].dueDate > block.timestamp;

        emit TaskDueDateVerified(_id, isValid);
        return isValid;
    }
}